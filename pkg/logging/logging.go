// Package logging wraps zerolog configuration used across binaries.
package logging

import (
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Setup sets console output and global level.
func Setup(level string) {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: zerolog.TimeFieldFormat})
	switch strings.ToLower(level) {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
		log.Trace().Msg("log level set to TRACE")
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("log level set to DEBUG")
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		log.Info().Msg("log level set to INFO")
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
		log.Warn().Msg("log level set to WARN")
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
		log.Error().Msg("log level set to ERROR")
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		log.Info().Msg("log level set to INFO")
	}
}
