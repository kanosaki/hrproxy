package main

import (
	"github.com/kanosaki/hrproxy"
	"github.com/Sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

func main() {
	logrus.SetLevel(logrus.DebugLevel)
	confBytes, err := ioutil.ReadFile("default.yaml")
	if err != nil {
		logrus.Fatalf("Failed to open config file")
	}
	var config hrproxy.Config
	if err := yaml.Unmarshal(confBytes, &config); err != nil {
		logrus.Fatalf("Failed to parse config file")
	}
	p, err := hrproxy.New(&config)
	if err != nil {
		panic(err)
	}
	go p.Start()
	if err := p.StartTLS(); err != nil {
		panic(err)
	}
}
