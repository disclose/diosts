package run

import (
	"github.com/hakluke/haksecuritytxt/pkg/securitytxt"
)

type Config struct {
	NumThreads int
	SecurityTxt securitytxt.Config
}

var DefaultConfig = Config{
	NumThreads: 8,
}

func NewConfig() *Config {
	config := DefaultConfig
	config.SecurityTxt = securitytxt.DefaultConfig

	return &config
}
