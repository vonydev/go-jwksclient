Client for JSON Web Key sets (JWKS).

## Main features

- Loads the key set from an URL in the background.
- Respects the cache control headers when present.
- Can be configured with optional minimum and maximum cache time limits.
- Has separate caching setting for errors.
- Logging using zerolog.

## Example usage

```go

cfg := jwksclient.NewConfig()
cfg.URL = "https://www.googleapis.com/oauth2/v3/certs"

jwksClient, err := jwksclient.New(cfg, &http.Client{})
if err != nil {
    panic(err)
}

// start the refresher in a separate goroutine
go func() {
    err := jwksClient.Refresher(context.Background())
    if err != nil {
        panic(err)
    }
}()

_, err := jwksClient.GetKeySet()
if err != nil {
    panic(err)
}

```

It is recommended that the library users always call GetKeySet() method before using the keys.

For a more complete example see the `example/` directory.