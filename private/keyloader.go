package private

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/dimovnike/go-jwksclient/keyfiles"

	"github.com/lestrrat-go/jwx/jwk"
)

/*
	this package watches a directory for changes and loads public keys from files in that directory
	file names must be the key name and the file content must be the key value

	key Id is derived from the file name, the .pub extension is removed if present
	to ignore a file, add a .ignore extension
*/

type Option func(*Keyloader)
type RefreshCallback func(jwk.Set)

func WithContext(ctx context.Context) Option {
	return func(kl *Keyloader) {
		kl.ctx = ctx
	}
}

func WithRefreshCallback(rcb RefreshCallback) Option {
	return func(kl *Keyloader) {
		kl.refreshCallback = rcb
	}
}

// WithWaitFirstFetch waits for the first fetch to complete before returning from New
func WithWaitFirstFetch() Option {
	return func(kl *Keyloader) {
		kl.waitFirstFetch = true
	}
}

// WithWaitGroup adds a wait group to the client, it will be done when the auto refresh stops
func WithWaitGroup(wg *sync.WaitGroup) Option {
	return func(kl *Keyloader) {
		kl.wg = wg
	}
}

type Keyloader struct {
	config Config

	ctx             context.Context
	wg              *sync.WaitGroup
	waitFirstFetch  bool
	refreshCallback RefreshCallback

	// the keys loaded from the directory
	keys              jwk.Set
	keysLoadTimestamp time.Time

	// the mutex to protect the keys and keysTimestamp
	m sync.RWMutex
}

func NewKeyloader(config Config, opts ...Option) (*Keyloader, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	kl := &Keyloader{
		config: config,
		ctx:    context.Background(),
	}

	for _, opt := range opts {
		opt(kl)
	}

	if kl.waitFirstFetch {
		if err := kl.LoadKeys(); err != nil {
			return nil, err
		}
	}

	if kl.wg != nil {
		kl.wg.Add(1)
	}
	go kl.LoadKeysWatch(kl.ctx)

	return kl, nil
}

func (kl *Keyloader) GetKeysLoadTime() time.Time {
	kl.m.RLock()
	defer kl.m.RUnlock()

	return kl.keysLoadTimestamp
}

// GetKeys returns a copy of the keys
func (kl *Keyloader) GetKeys() (jwk.Set, time.Time, error) {
	kl.m.RLock()
	defer kl.m.RUnlock()

	if kl.keys == nil {
		return nil, time.Time{}, errors.New("keys not loaded")
	}

	return kl.keys, kl.keysLoadTimestamp, nil
}

// LoadKeysWatch starts watching the directory for changes and loads the keys
// it honors the FailOnError config option
func (kl *Keyloader) LoadKeysWatch(ctx context.Context) error {
	watcher := keyfiles.NewWatcher()
	logger := kl.config.Logger

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg *sync.WaitGroup
	if kl.wg != nil {
		wg = kl.wg
	} else {
		wg = &sync.WaitGroup{}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := watcher.Watch(ctx, kl.config.Dir, kl.config.WatchInterval)
		logger.Debug().Err(err).Msg("watcher goroutine exited")

		cancel()
	}()

	logger.Info().Str("dir", kl.config.Dir).Dur("interval", kl.config.WatchInterval).Msg("started watching directory for changes")
	defer logger.Info().Msg("stopped watching directory for changes")

	var retErr error

	// watcher will close the channel when done
	for event := range watcher.Events {
		if event.Error != nil {
			if kl.config.FailOnError {
				retErr = event.Error
				cancel()
				break
			}

			logger.Error().Err(event.Error).Msg("watcher event error")
			continue
		}

		if err := kl.LoadKeys(); err != nil {
			retErr = err
			cancel()
			break
		}

		if kl.refreshCallback != nil {
			ks, _, err := kl.GetKeys()
			if err != nil {
				logger.Error().Err(err).Msg("failed to get keys")
				continue
			}

			kl.refreshCallback(ks)
		}
	}

	logger.Info().Str("dir", kl.config.Dir).Msg("stopping watching directory for changes ...")

	if kl.wg != nil {
		kl.wg.Done()
	} else {
		wg.Wait()
	}

	return retErr
}

// LoadKeysOnce loads the keys once
// it honors the FailOnError config option
func (kl *Keyloader) LoadKeys() error {
	keys, err := kl.loadKeys(kl.config.Dir)
	if err != nil {
		if kl.config.FailOnError {
			return err
		}

		kl.config.Logger.Error().Err(err).Msg("failed to load keys")
		return nil // leave the old keys
	}

	kl.m.Lock()
	defer kl.m.Unlock()

	kl.keys = keys
	kl.keysLoadTimestamp = time.Now()

	if kl.refreshCallback != nil {
		kl.refreshCallback(keys)
	}

	return nil
}
