package hrproxy

import (
	elastic "gopkg.in/olivere/elastic.v5"
)

type Config struct {
	AcmeUrl       string `yaml:"acme_url"`
	TlsKey        string `yaml:"tls_key"`
	TlsCert       string `yaml:"tls_cert"`
	CommonName    string `yaml:"common_name"`
	Proxies       map[string]*ProxyConfig `yaml:"proxies"`
	Elasticsearch *ElasticsearchConfig `yaml:"elasticsearch"`
}

type ProxyConfig struct {
	URL string `yaml:"url"`
}

type ElasticsearchConfig struct {
	URL  string `yaml:"url"`
	User string `yaml:"user"`
	Pass string `yaml:"pass"`
}

func (ec *ElasticsearchConfig) NewClient() (*elastic.Client, error) {
	opts := []elastic.ClientOptionFunc {
		elastic.SetURL(ec.URL),
	}
	if len(ec.User) > 0 {
		opts = append(opts, elastic.SetBasicAuth(ec.User, ec.Pass))
	}
	return elastic.NewClient(opts...)
}
