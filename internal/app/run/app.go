package run

type App struct {
	*Config
}

func New(config *Config) (*App, error) {
	a := &App{
		Config: config,
	}

	return a, nil
}

func (a *App) Run() error {
	return nil
}
