package hrproxy

import (
	"crypto/x509"
	"github.com/ericchiang/letsencrypt"
	"github.com/pkg/errors"
	"crypto/rand"
	"crypto/x509/pkix"
	"sync"
	"encoding/pem"
	"github.com/Sirupsen/logrus"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"io/ioutil"
	"time"
)

type AcmeClient struct {
	acmeDirectory     string
	mu                *sync.Mutex
	commonName        string
	hosts             []string
	resp              *letsencrypt.CertificateResponse
	challengePath     string
	challengeResource string
	privateKey        *ecdsa.PrivateKey
	certificate       *x509.Certificate
	certPath          string
	keyPath           string
	log               *logrus.Entry
}

func NewAcmeClient(acmeDirectory, commonName, certPath, keyPath string) (*AcmeClient, error) {
	ac := &AcmeClient{
		acmeDirectory: acmeDirectory,
		certPath:      certPath,
		keyPath:       keyPath,
		mu:            &sync.Mutex{},
		commonName:    commonName,
		log:           logrus.WithField("at", "acme"),
	}
	if err := ac.load(); err != nil {
		return nil, err
	}
	return ac, nil
}

func (ac *AcmeClient) load() error {
	keyFileData, err := ioutil.ReadFile(ac.keyPath)
	if err == nil {
		ac.privateKey, err = x509.ParseECPrivateKey(keyFileData)
		if err != nil {
			return err
		}
	}
	certFileData, err := ioutil.ReadFile(ac.certPath)
	if err == nil {
		cert, err := x509.ParseCertificate(certFileData)
		if err != nil {
			return err
		}
		ac.setCertificate(cert)
	}
	return nil
}

func (ac *AcmeClient) save() error {
	keyBytes, err := x509.MarshalECPrivateKey(ac.privateKey)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal EC private key")
	}
	if err := ioutil.WriteFile(ac.keyPath, keyBytes, 0600); err != nil {
		return errors.Wrapf(err, "Failed to save private key to %s", ac.keyPath)
	}
	if err := ioutil.WriteFile(ac.certPath, ac.certificate.Raw, 0600); err != nil {
		return errors.Wrapf(err, "Failed to save certificate key to %s", ac.certPath)
	}
	return nil
}

func (ac *AcmeClient) HasValidCertificate(hosts []string) bool {
	if ac.certificate == nil {
		return false
	}
	if ac.privateKey == nil {
		return false
	}
	now := time.Now()
	cert := ac.certificate
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return false
	}
	fqdns := make(map[string]bool, len(cert.DNSNames))
	for _, fqdn := range cert.DNSNames {
		fqdns[fqdn] = true
	}
	for _, host := range hosts {
		active, ok := fqdns[host]
		if !ok || !active {
			return false
		}
	}
	return true
}

func (ac *AcmeClient) GetValidCertificate(hosts []string) (tls.Certificate, error) {
	if !ac.HasValidCertificate(hosts) {
		if err := ac.refresh(hosts); err != nil {
			return tls.Certificate{}, errors.Wrap(err, "ACME refresh failed")
		}
	}
	keyBytes, err := x509.MarshalECPrivateKey(ac.privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ac.certificate.Raw})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return tls.X509KeyPair(certPem, keyPem)
}

func (ac *AcmeClient) setCertificate(cert *x509.Certificate) {
	ac.certificate = cert
	// TODO: init refresh timer here
	now := time.Now()
	ac.log.Infof("Certificate is active for %s (until %s)", cert.NotAfter.Sub(now).String(), cert.NotAfter)
	ac.log.Infof("Active FQDNs: %s + %s", cert.DNSNames, cert.PermittedDNSDomains)
}

func (ac *AcmeClient) refresh(hosts []string) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	log := ac.log.WithField("tag", "acme_update")
	log.Debugf("Initializing...")
	if err := ac.initPrivateKey(); err != nil {
		return err
	}
	cli, err := letsencrypt.NewClient(ac.acmeDirectory)
	if err != nil {
		return errors.Wrap(err, "Failed to start new acme client")
	}

	log.Debugf("Generating private key")
	// Let's encrypt doesn't supports P521 curves
	accountKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return errors.Wrap(err, "Failed to generate private key")
	}

	log.Debugf("Requesting authorization")
	if _, err := cli.NewRegistration(accountKey); err != nil {
		return errors.Wrap(err, "Failed to registration.")
	}

	for _, host := range append(hosts, ac.commonName) {
		log.Infof("Authorizing %s", host)
		auth, _, err := cli.NewAuthorization(accountKey, "dns", host)
		if err != nil {
			return errors.Wrap(err, "Failed to authorization")
		}

		chals := auth.Combinations(letsencrypt.ChallengeHTTP)
		if len(chals) == 0 {
			return errors.New("No supported challenge combinations.")
		}
		if len(chals[0]) != 1 && chals[0][0].Type != letsencrypt.ChallengeHTTP {
			return errors.New("Unsupported challenge combinations")
		}
		chal := chals[0][0]
		ac.challengePath, ac.challengeResource, err = chal.HTTP(accountKey)
		if err != nil {
			return err
		}
		log.Debugf("Waiting challenges...")
		if err := cli.ChallengeReady(accountKey, chal); err != nil {
			return err
		}
	}

	csr, err := ac.newCSR(hosts)
	if err != nil {
		return errors.Wrap(err, "Failed to generate new CSR")
	}

	log.Debugf("Requesting certificates..")
	cert, err := cli.NewCertificate(accountKey, csr)
	if err != nil {
		return errors.Wrap(err, "Failed to request certificate")
	}
	ac.setCertificate(cert.Certificate)
	log.Debugf("Request done, saving...")
	if err := ac.save(); err != nil {
		return err
	}
	return nil
}

func (ac *AcmeClient) initPrivateKey() error {
	//certKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	certKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return errors.Wrap(err, "Failed to generate private key")
	}
	ac.privateKey = certKey
	return nil
}

func (ac *AcmeClient) newCSR(hosts []string) (*x509.CertificateRequest, error) {
	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          &ac.privateKey.PublicKey,
		Subject:            pkix.Name{CommonName: ac.commonName},
		DNSNames:           hosts,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, ac.privateKey)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	return csr, nil
}
