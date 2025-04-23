package run

import (
	"github.com/disclose/diosts/pkg/securitytxt"
)

var DefaultConfig = Config{
	NumThreads:  8,
	SecurityTxt: securitytxt.Config{},
}

// Config for the application
type Config struct {
	// Number of threads for scraping
	NumThreads int

	// Output path for non-RFC compliant security.txt files
	NonCompliantOutputPath string

	// Domain client config
	SecurityTxt securitytxt.Config
}

func NewConfig() *Config {
	c := DefaultConfig
	return &c
}
