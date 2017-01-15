package hrproxy

import (
	"github.com/braintree/manners"
	"github.com/Sirupsen/logrus"
	"net/url"
	"crypto/tls"
	"net"
	"net/http"
	"io"
)

type HRProxy struct {
	pubServer *manners.GracefulServer
	server    *manners.GracefulServer
	acme      *AcmeClient
	conf      *Config
}

func New(conf *Config) (*HRProxy, error) {
	acme, err := NewAcmeClient(conf.AcmeUrl, conf.CommonName, conf.TlsCert, conf.TlsKey)
	if err != nil {
		return nil, err
	}
	return &HRProxy{
		conf:      conf,
		acme:      acme,
		pubServer: manners.NewServer(),
		server:    manners.NewServer(),
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
	mux := NewHostMux()
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
	log := logrus.WithField("tag", "http")
	hrp.pubServer.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := logRequest(log, r)
		if r.URL.Path == hrp.acme.challengePath {
			// ACME HTTP challenge response.
			if _, err := io.WriteString(w, hrp.acme.challengeResource); err != nil {
				l.WithField("code", 500).Infof("Failed to response challenge")
			} else {
				l.WithField("code", 200).Infof("")
			}
		} else {
			// Redirect to HTTPS
			var u url.URL
			u.Scheme = "https"
			u.Host = r.Host
			u.Path = r.URL.Path
			u.RawQuery = r.URL.RawQuery
			u.Fragment = r.URL.Fragment
			l.WithField("code", http.StatusMovedPermanently).Infof("")
			http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
		}
	})
	if err := hrp.pubServer.ListenAndServe(); err != nil {
		logrus.Error(err)
	}
}

func logRequest(log *logrus.Entry, r *http.Request) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"method":      r.Method,
		"host":        r.Host,
		"referer":     r.Referer(),
		"request":     r.RequestURI,
		"remote_addr": r.RemoteAddr,
		"user_agent":  r.Header["User-Agent"],
	})
}
