package keyfiles

import (
	"bytes"
	"context"
	"errors"
	"time"
)

type WatcherEvent struct {
	Files   FileMetadatas
	Skipped map[string]string
	Error   error
}

type Watcher struct {
	Events <-chan WatcherEvent
	events chan<- WatcherEvent
}

func NewWatcher() *Watcher {
	ch := make(chan WatcherEvent)

	w := &Watcher{
		Events: ch,
		events: ch,
	}

	return w
}

func (w *Watcher) Watch(ctx context.Context, dir string, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("watcher can not be started with interval <= 0")
	}

	defer close(w.events)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	oldHash := []byte{}
	oldErrStr := ""

	check := func() {
		files, skipped, err := GetFileMetadata(dir)

		if err != nil && err.Error() == oldErrStr {
			// have error, but it's the same as last time
			return
		}

		hash, err := files.Hash()
		if err != nil && err.Error() == oldErrStr {
			// have error, but it's the same as last time
			return
		}

		oldErrStr = ""

		if err != nil {
			oldErrStr = err.Error()
			oldHash = nil
		} else {
			oldErrStr = ""
			if bytes.Equal(hash, oldHash) {
				// no changes
				return
			}
		}

		oldHash = hash

		w.events <- WatcherEvent{
			Files:   files,
			Skipped: skipped,
			Error:   err,
		}
	}

	check()

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-ticker.C:
			check()
		}
	}

}
