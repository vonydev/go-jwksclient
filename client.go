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
	All exported methods are safe for concurrent use.
	For more details see Config and example/main.go
*/

type Option func(*Client)
type RefreshCallback func(ns jwk.Set, err error)

// WithContext sets the context for the client
func WithContext(ctx context.Context) Option {
	return func(c *Client) {
		c.ctx = ctx
	}
}

// WithAutoRefresh start a refresh goroutine that will refresh the JWKS in the background
func WithAutoRefresh(interval time.Duration) Option {
	return func(c *Client) {
		c.autoRefreshInterval = interval
	}
}

// WithAutoRefreshCallback sets a custom auto refresh callback, it will be called when keys change
func WithAutoRefreshCallback(rcb RefreshCallback) Option {
	return func(c *Client) {
		c.rcb = rcb
	}
}

// WithWaitGroup adds a wait group to the client, it will be done when the auto refresh stops
func WithWaitGroup(wg *sync.WaitGroup) Option {
	return func(c *Client) {
		c.wg = wg
	}
}

// WithHttpClient sets the http client to use, if not specified the default client is used
func WithHttpClient(client *http.Client) Option {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithWaitFirstFetch waits for the first fetch to complete before returning from New
func WithWaitFirstFetch() Option {
	return func(c *Client) {
		c.waitFirstFetch = true
	}
}

type Client struct {
	config Config

	ctx                 context.Context
	waitFirstFetch      bool
	autoRefreshInterval time.Duration
	wg                  *sync.WaitGroup
	rcb                 RefreshCallback

	httpClient *http.Client
	refresh    func() (bool, error)

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
func New(config Config, opts ...Option) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	cl := &Client{
		config:     config,
		httpClient: http.DefaultClient,
		ctx:        context.Background(),
	}

	for _, opt := range opts {
		opt(cl)
	}

	cl.refresh = func() (bool, error) {
		refreshed, err := cl.Refresh(false)
		if err != nil {
			if cl.config.ExitOnError {
				return false, err
			}

			log.Error().Err(err).Msg("failed to refresh JWKS")

			return false, nil
		}

		if refreshed {
			log.Info().Msg("JWKS refreshed")
		}

		return refreshed, nil
	}

	if cl.waitFirstFetch {
		if _, err := cl.refresh(); err != nil {
			return cl, err
		}
	}

	if cl.autoRefreshInterval > 0 {
		if cl.wg != nil {
			cl.wg.Add(1)
		}

		go cl.autoRefresh()
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

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-tick.C:
			if _, err := c.refresh(); err != nil {
				return err
			}
		}
	}
}

// Refresh fetches the JWKS from the endpoint and updates the cache
func (c *Client) Refresh(force bool) (refreshed bool, _err error) {
	c.m.RLock()
	cacheExpiresAfter := c.cacheExpiresAfter
	c.m.RUnlock()

	if !force && !time.Now().After(cacheExpiresAfter) {
		// cache is still valid
		return false, nil
	}

	ks, resp, headers, err := c.get()

	c.m.Lock()
	defer c.m.Unlock()

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
	req, err := http.NewRequestWithContext(c.ctx, "GET", c.config.URL, http.NoBody)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
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
