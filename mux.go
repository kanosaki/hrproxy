package hrproxy

import (
	"net/http"
	"net/url"
	"time"
	"strings"
	"io"
	"net"
	"sync"
	"github.com/Sirupsen/logrus"
)

type HostMux struct {
	proxies map[string]*ReverseProxy
	bufpool *BufferPool
	log     *logrus.Entry
}

func NewHostMux() *HostMux {
	return &HostMux{
		proxies: make(map[string]*ReverseProxy),
		bufpool: NewBufferPool(100, 32*1024), // 100 x 32KiB buffers
		log:     logrus.WithField("tag", "web"),
	}
}

func (m HostMux) AddProxy(host string, url *url.URL) {
	m.proxies[host] = NewReverseProxy(url, m.bufpool)
}

func (m *HostMux) mkLogger(req *http.Request) *logrus.Entry {
	return logRequest(m.log, req)
}

func (m *HostMux) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	log := m.mkLogger(req)
	host := req.Host
	if len(host) == 0 {
		w.WriteHeader(500)
		log.WithField("code", 500).Infof("")
		return
	}
	if prox, ok := m.proxies[host]; ok {
		begin := time.Now()
		res := prox.ServeHTTP(w, req)
		elapsed := time.Now().Sub(begin)
		var code int
		if res == nil {
			code = 500
		} else {
			code = res.StatusCode
		}
		log.WithFields(logrus.Fields{
			"code":       code,
			"elapsed_ms": float32(elapsed.Nanoseconds()) / 1000 / 1000,
		}).Info("")
	} else {
		w.WriteHeader(404)
		log.WithField("code", 404).Infof("")
	}
}

// onExitFlushLoop is a callback set by tests to detect the state of the
// flushLoop() goroutine.
var onExitFlushLoop func()

// ReverseProxy is an HTTP Handler that takes an incoming request and
// sends it to another server, proxying the response back to the
// client.
type ReverseProxy struct {
	target *url.URL

	// The transport used to perform proxy requests.
	// If nil, http.DefaultTransport is used.
	Transport http.RoundTripper

	// FlushInterval specifies the flush interval
	// to flush to the client while copying the
	// response body.
	// If zero, no periodic flushing is done.
	FlushInterval time.Duration

	// BufferPool optionally specifies a buffer pool to
	// get byte slices for use by io.CopyBuffer when
	// copying HTTP response bodies.
	BufferPool *BufferPool
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// NewSingleHostReverseProxy returns a new ReverseProxy that routes
// URLs to the scheme, host, and base path provided in target. If the
// target's path is "/base" and the incoming request was for "/dir",
// the target request will be for /base/dir.
// NewSingleHostReverseProxy does not rewrite the Host header.
// To rewrite Host headers, use ReverseProxy directly with a custom
// Director policy.
func NewReverseProxy(target *url.URL, pool *BufferPool) *ReverseProxy {
	return &ReverseProxy{target: target, BufferPool: pool}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; http://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

type requestCanceler interface {
	CancelRequest(*http.Request)
}

type runOnFirstRead struct {
	io.Reader // optional; nil means empty body

	fn func() // Run before first Read, then set to nil
}

func (c *runOnFirstRead) Read(bs []byte) (int, error) {
	if c.fn != nil {
		c.fn()
		c.fn = nil
	}
	if c.Reader == nil {
		return 0, io.EOF
	}
	return c.Reader.Read(bs)
}

func (p *ReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) *http.Response {
	transport := p.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	outreq := new(http.Request)
	*outreq = *req // includes shallow copies of maps, but okay

	if closeNotifier, ok := rw.(http.CloseNotifier); ok {
		if requestCanceler, ok := transport.(requestCanceler); ok {
			reqDone := make(chan struct{})
			defer close(reqDone)

			clientGone := closeNotifier.CloseNotify()

			outreq.Body = struct {
				io.Reader
				io.Closer
			}{
				Reader: &runOnFirstRead{
					Reader: outreq.Body,
					fn: func() {
						go func() {
							select {
							case <-clientGone:
								requestCanceler.CancelRequest(outreq)
							case <-reqDone:
							}
						}()
					},
				},
				Closer: outreq.Body,
			}
		}
	}
	target := p.target
	targetQuery := target.RawQuery
	outreq.URL.Scheme = target.Scheme
	outreq.URL.Host = target.Host
	outreq.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
	if targetQuery == "" || outreq.URL.RawQuery == "" {
		outreq.URL.RawQuery = targetQuery + outreq.URL.RawQuery
	} else {
		outreq.URL.RawQuery = targetQuery + "&" + outreq.URL.RawQuery
	}
	if _, ok := outreq.Header["User-Agent"]; !ok {
		// explicitly disable User-Agent so it's not set to default value
		outreq.Header.Set("User-Agent", "")
	}
	outreq.Proto = "HTTP/1.1"
	outreq.ProtoMajor = 1
	outreq.ProtoMinor = 1
	outreq.Close = false

	// Remove hop-by-hop headers to the backend. Especially
	// important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us. This
	// is modifying the same underlying map from req (shallow
	// copied above) so we only copy it if necessary.
	copiedHeaders := false
	for _, h := range hopHeaders {
		if outreq.Header.Get(h) != "" {
			if !copiedHeaders {
				outreq.Header = make(http.Header)
				copyHeader(outreq.Header, req.Header)
				copiedHeaders = true
			}
			outreq.Header.Del(h)
		}
	}

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := outreq.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		outreq.Header.Set("X-Forwarded-For", clientIP)
	}

	res, err := transport.RoundTrip(outreq)
	if err != nil {
		rw.WriteHeader(http.StatusBadGateway)
		return nil
	}

	for _, h := range hopHeaders {
		res.Header.Del(h)
	}

	copyHeader(rw.Header(), res.Header)

	// The "Trailer" header isn't included in the Transport's response,
	// at least for *http.Transport. Build it up from Trailer.
	if len(res.Trailer) > 0 {
		var trailerKeys []string
		for k := range res.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		rw.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

	rw.WriteHeader(res.StatusCode)
	if len(res.Trailer) > 0 {
		// Force chunking if we saw a response trailer.
		// This prevents net/http from calculating the length for short
		// bodies and adding a Content-Length.
		if fl, ok := rw.(http.Flusher); ok {
			fl.Flush()
		}
	}
	p.copyResponse(rw, res.Body)
	res.Body.Close() // close now, instead of defer, to populate res.Trailer
	copyHeader(rw.Header(), res.Trailer)
	return res
}

func (p *ReverseProxy) copyResponse(dst io.Writer, src io.Reader) {
	if p.FlushInterval != 0 {
		if wf, ok := dst.(writeFlusher); ok {
			mlw := &maxLatencyWriter{
				dst:     wf,
				latency: p.FlushInterval,
				done:    make(chan bool),
			}
			go mlw.flushLoop()
			defer mlw.stop()
			dst = mlw
		}
	}

	var buf []byte
	buf = p.BufferPool.Get()
	io.CopyBuffer(dst, src, buf)
	p.BufferPool.Put(buf)
}

type writeFlusher interface {
	io.Writer
	http.Flusher
}

type maxLatencyWriter struct {
	dst     writeFlusher
	latency time.Duration

	mu   sync.Mutex // protects Write + Flush
	done chan bool
}

func (m *maxLatencyWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dst.Write(p)
}

func (m *maxLatencyWriter) flushLoop() {
	t := time.NewTicker(m.latency)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			if onExitFlushLoop != nil {
				onExitFlushLoop()
			}
			return
		case <-t.C:
			m.mu.Lock()
			m.dst.Flush()
			m.mu.Unlock()
		}
	}
}

func (m *maxLatencyWriter) stop() { m.done <- true }
