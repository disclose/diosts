package run

type Config struct {
	NumThreads int
}

var DefaultConfig = Config{
	NumThreads: 8,
}

func NewConfig() *Config {
	config := DefaultConfig
	return &config
}
