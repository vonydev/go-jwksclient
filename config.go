package jwksclient

import (
	"errors"
	"time"
)

type Config struct {
	// URL of the JWKS endpoint
	URL string

	// cache successful requests at least for this duration regardles of cache headers
	CacheMin time.Duration

	// cache successful requests at most for this duration regardles of cache headers, 0 means caching is disabled
	CacheMax time.Duration

	// cache failed responses (connection and HTTP errors) for this duration, 0 means no caching for errors
	CacheErrors time.Duration

	// ExitOnError will cause the Refresher() method to return an error if the JWKS can't be fetched
	ExitOnError bool

	// keep the old keys for this duration after an error, 0 means no caching of stale keys
	KeepStaleKeys time.Duration
}

// NewConfig creates a new Config with default values
func NewConfig() Config {
	return Config{
		CacheMin:      time.Minute,
		CacheMax:      time.Hour,
		CacheErrors:   30 * time.Second,
		KeepStaleKeys: 5 * time.Minute,
	}
}

func (c Config) Validate() error {
	if c.URL == "" {
		return errors.New("URL is required")
	}

	return nil
}
