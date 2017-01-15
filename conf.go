package hrproxy

type Config struct {
	AcmeUrl    string `yaml:"acme_url"`
	TlsKey     string `yaml:"tls_key"`
	TlsCert    string `yaml:"tls_cert"`
	CommonName string `yaml:"common_name"`
	Proxies    map[string]*ProxyConfig `yaml:"proxies"`
}

type ProxyConfig struct {
	URL string
}
