package commands

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/disclose/diosts/internal/app/run"
)

var runConfig = run.NewConfig()

var rootCmd = &cobra.Command{
	Use: "diosts",
	Short: "Scrape security.txt from list of input domains on stdin",
	Run: func(cmd *cobra.Command, args []string) {
		onRun()
	},
}

var debug bool

func init() {
	cobra.OnInitialize(initApp)

	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Debug logging")

	rootCmd.Flags().IntVarP(&runConfig.NumThreads,
		"threads", "t",
		run.DefaultConfig.NumThreads,
		"Number of concurrent scraping threads",
	)

	rootCmd.Flags().BoolVar(&runConfig.SecurityTxt.StrictRedirect,
		"strict-redirect",
		false,
		"Only allow redirects to same base domain",
	)
}

func initApp() {
	// This is where we would deal with config files if we were so inclined

	// Set log level
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

func Execute(version string) {
	rootCmd.Version = version

	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("")
	}
}

func onRun() {
	app, err := run.New(runConfig)
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}

	if err := app.Run(); err != nil {
		log.Fatal().Err(err).Msg("")
	}

	log.Info().Msg("all done. bye bye!")
}
