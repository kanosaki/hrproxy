package hrproxy

import (
	"github.com/braintree/manners"
	"github.com/Sirupsen/logrus"
	"net/url"
	"crypto/tls"
	"net"
	"net/http"
	"io"
	elastic "gopkg.in/olivere/elastic.v5"
	"time"
)

type HRProxy struct {
	pubServer *manners.GracefulServer
	server    *manners.GracefulServer
	acme      *AcmeClient
	conf      *Config
	es        *elastic.Client
	access    *ESLogger
}

func New(conf *Config) (*HRProxy, error) {
	acme, err := NewAcmeClient(conf.AcmeUrl, conf.CommonName, conf.TlsCert, conf.TlsKey)
	if err != nil {
		return nil, err
	}
	es, err := conf.Elasticsearch.NewClient()
	if err != nil {
		return nil, err
	}
	access := NewESLogger(es, 100, 30*time.Second, "pub-access")
	return &HRProxy{
		conf:         conf,
		acme:         acme,
		pubServer:    manners.NewServer(),
		server:       manners.NewServer(),
		es:           es,
		access:       access,
	}, nil
}

// ListenAndServeTLS provides a graceful equivalent of net/http.Serve.ListenAndServeTLS.
func (hrp *HRProxy) ListenAndServeTLS() error {
	hosts := make([]string, 0, len(hrp.conf.Proxies))
	for h := range hrp.conf.Proxies {
		hosts = append(hosts, h)
	}
	// direct lift from net/http/server.go
	config := &tls.Config{}
	config.NextProtos = []string{"h2", "http/1.1"}
	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = hrp.acme.GetValidCertificate(hosts)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", "0.0.0.0:443")
	if err != nil {
		return err
	}
	return hrp.server.Serve(tls.NewListener(ln, config))
}

func (hrp *HRProxy) StartTLS() error {
	mux := NewHostMux(hrp.es)
	for host, proxy := range hrp.conf.Proxies {
		u, err := url.Parse(proxy.URL)
		if err != nil {
			return err
		}
		mux.AddProxy(host, u)
	}
	hrp.server.Handler = mux
	logrus.Infof("Starting HTTP Server")
	return hrp.ListenAndServeTLS()
}

// HTTP server has only 2 functions.
// 1. Response ACME HTTP challenge.
// 2. Redirect any other requests to HTTPS.
func (hrp *HRProxy) Start() {
	hrp.pubServer.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var code int
		begin := time.Now()
		if r.URL.Path == hrp.acme.challengePath {
			// ACME HTTP challenge response.
			if _, err := io.WriteString(w, hrp.acme.challengeResource); err != nil {
				code = 500
			} else {
				code = 200
			}
		} else {
			if _, ok := hrp.conf.Proxies[r.Host]; ok {
				// Redirect to HTTPS
				var u url.URL
				u.Scheme = "https"
				u.Host = r.Host
				u.Path = r.URL.Path
				u.RawQuery = r.URL.RawQuery
				u.Fragment = r.URL.Fragment
				http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
				code = http.StatusMovedPermanently
			} else {
				hj, _ := w.(http.Hijacker)
				conn, _, _ := hj.Hijack()
				conn.Close()
				code = -1
			}
		}
		hrp.access.Add(r, code, begin, time.Now())
	})
	if err := hrp.pubServer.ListenAndServe(); err != nil {
		logrus.Error(err)
	}
}
