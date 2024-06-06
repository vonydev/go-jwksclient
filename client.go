package jwksclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
)

/*
	Client is a JWKS client that fetches and caches keys from a JWKS endpoint.
	It respects the Cache-Control and Expires headers but also allows for min and max cache limits.
	For more details see Config and example/main.go
*/

type Client struct {
	config Config

	httpClient *http.Client

	// cached data
	m                 sync.RWMutex
	cacheExpiresAfter time.Time
	cachedResponse    []byte
	cachedHeaders     http.Header
	cachedJWKSet      jwk.Set
	cachedError       error
	keysStaleSince    time.Time
}

// New creates a new JWKS client
func New(config Config, client *http.Client) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	cl := &Client{
		config:     config,
		httpClient: client,
	}

	return cl, nil
}

// GetKeySet returns the loaded key set
func (c *Client) GetKeySet() (jwk.Set, error) {
	c.m.RLock()
	defer c.m.RUnlock()

	if c.cachedError != nil && (c.keysStaleSince.Add(c.config.KeepStaleKeys).Before(time.Now()) || c.cachedJWKSet == nil) {
		return nil, c.cachedError
	}

	if c.cachedJWKSet == nil {
		return nil, &ErrKeysNotFetched{}
	}

	return c.cachedJWKSet, nil
}

// returns all loaded data, useful for debugging
func (c *Client) GetAll() (jwk.Set, http.Header, []byte, error) {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.cachedJWKSet, c.cachedHeaders, c.cachedResponse, c.cachedError
}

// Refresher is a blocking function that refreshes the JWKS in the background
// it honors the ExitOnError config option
// it exits when the context is canceled
func (c *Client) Refresher(ctx context.Context) error {
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()

	refresh := func() error {
		refreshed, err := c.Refresh(false)
		if err != nil {
			if c.config.ExitOnError {
				return err
			}

			log.Error().Err(err).Msg("failed to refresh JWKS")
			return nil
		}

		if refreshed {
			log.Info().Msg("JWKS refreshed")
		}

		return nil
	}

	if err := refresh(); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-tick.C:
			if err := refresh(); err != nil {
				return err
			}
		}
	}
}

// Refresh fetches the JWKS from the endpoint and updates the cache
func (c *Client) Refresh(force bool) (refreshed bool, _err error) {
	c.m.Lock()
	defer c.m.Unlock()

	if !force && !time.Now().After(c.cacheExpiresAfter) {
		// cache is still valid
		return false, nil
	}

	ks, resp, headers, err := c.get()

	if err != nil && c.keysStaleSince.IsZero() {
		// update stale keys timestamp on the first error
		c.keysStaleSince = time.Now()
	}

	c.cachedHeaders = headers
	c.cachedResponse = resp
	c.cachedError = err

	if err == nil {
		c.keysStaleSince = time.Time{}
		c.cachedJWKSet = ks
	}

	c.updateExpiresAfter(headers, err)

	return true, err
}

// get performs a GET request and returns the raw body, headers and the JWK set
func (c *Client) get() (jwkSet jwk.Set, responseBody []byte, headers http.Header, _err error) {
	resp, err := c.httpClient.Get(c.config.URL)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("performing request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, resp.Header, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, body, resp.Header, fmt.Errorf("unexpected HTTP status code: %d", resp.StatusCode)
	}

	kSet := jwk.NewSet()

	if err := json.Unmarshal(body, kSet); err != nil {
		return nil, body, resp.Header, fmt.Errorf("unmarshalling JSON: %w", err)
	}

	return kSet, body, resp.Header, nil
}

func (c *Client) updateExpiresAfter(headers http.Header, err error) {
	now := time.Now()

	if err != nil {
		if c.config.CacheErrors > 0 {
			c.cacheExpiresAfter = now.Add(c.config.CacheErrors)
		}
		return
	}

	var cacheMinHit, cacheMaxHit, cacheHeadersPresent bool

	headersExpiresAfter, err := expiresAfter(now, headers)

	expiresAfter := headersExpiresAfter

	if err != nil {
		expiresAfter = now.Add(c.config.CacheMin)
	} else {
		cacheHeadersPresent = true

		if now.Add(c.config.CacheMax).Before(expiresAfter) {
			cacheMaxHit = true
			expiresAfter = now.Add(c.config.CacheMax)
		}

		if expiresAfter.Before(now.Add(c.config.CacheMin)) {
			cacheMinHit = true
			expiresAfter = now.Add(c.config.CacheMin)
		}
	}

	l := log.Debug().
		Err(err).
		Time("expiresAfter", expiresAfter).
		Dur("refreshAfter", expiresAfter.Sub(now)).
		Bool("cacheMinHit", cacheMinHit).
		Bool("cacheMaxHit", cacheMaxHit).
		Bool("cacheHeadersPresent", cacheHeadersPresent)

	if cacheHeadersPresent {
		l = l.Dur("refreshAfterHeaders", headersExpiresAfter.Sub(now))
	}

	l.Msg("cache headers parsed")

	c.cacheExpiresAfter = expiresAfter
}
