package main

import (
	"context"
	"flag"
	"os"
	"time"

	"github.com/dimovnike/go-jwksclient"
	"github.com/dimovnike/go-jwksclient/private"
	"github.com/rs/zerolog"
)

var log = zerolog.New(os.Stderr).
	Level(zerolog.DebugLevel).
	With().
	Timestamp().
	Caller().
	Logger().
	Output(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: zerolog.TimeFieldFormat,
	})

func makeConfig() jwksclient.Config {
	cfg := jwksclient.NewConfig()
	p := private.Config{}
	_ = p

	const defaultURL = "https://www.googleapis.com/oauth2/v3/certs"

	flag.StringVar(&cfg.URL, "url", defaultURL, "JWKS URL")
	flag.DurationVar(&cfg.CacheMin, "cache-min", cfg.CacheMin, "CacheMin")
	flag.DurationVar(&cfg.CacheMax, "cache-max", cfg.CacheMax, "CacheMax")
	flag.DurationVar(&cfg.CacheErrors, "cache-errors", cfg.CacheErrors, "CacheErrors")
	flag.BoolVar(&cfg.ExitOnError, "exit-on-error", cfg.ExitOnError, "ExitOnError")
	flag.DurationVar(&cfg.KeepStaleKeys, "keep-stale-keys", cfg.KeepStaleKeys, "KeepStaleKeys")

	flag.Parse()

	return cfg
}

func main() {
	jwksclient.SetLogger(log)

	cfg := makeConfig()

	log.Debug().Interface("config", cfg).Msg("current config")

	jwksClient, err := jwksclient.New(cfg)
	if err != nil {
		panic(err)
	}

	// this is expected to fail because refresher is not running yet
	if _, err := jwksClient.GetKeySet(); err != nil {
		log.Error().Err(err).Msg("get keys without refresher test")
	}

	exitCh := make(chan error)

	// start the refresher in a separate goroutine
	go func() {
		exitCh <- jwksClient.Refresher(context.Background())
	}()

	tick := time.NewTicker(1 * time.Second)

	for {
		select {
		case err := <-exitCh:
			log.Info().Err(err).Msg("refresher exited")
			return

		case <-tick.C:
			_, err := jwksClient.GetKeySet()
			if err != nil {
				log.Error().Err(err).Msg("failed to get keys")
			}
		}
	}
}
