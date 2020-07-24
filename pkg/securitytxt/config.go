package securitytxt

import (
	"time"
)

type Config struct {
	DialTimeout time.Duration
	RequestTimeout time.Duration
	TLSHandshakeTimeout time.Duration
	Insecure bool
}

var DefaultConfig = Config{
	DialTimeout: 20 * time.Second,
	RequestTimeout: 10 * time.Second,
	TLSHandshakeTimeout: 5 * time.Second,
	Insecure: false,
}

func NewConfig() *Config {
	config := DefaultConfig
	return &config
}
