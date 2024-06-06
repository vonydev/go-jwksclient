package jwksclient

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	headerNameCacheControl = "Cache-Control"
	headerNameAge          = "Age"
	headerNameExpires      = "Expires"

	cacheControlFieldMaxAge  = "max-age"
	cacheControlFieldSMaxAge = "s-maxage"
)

// expiresAfter calculates the cache exipration time based on Cache-Control and Expires headers
// see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
func expiresAfter(now time.Time, headers http.Header) (time.Time, error) {
	maxAge, maxAgeOk, err := parseMaxAge(headers)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing max-age: %w", err)
	}

	if maxAgeOk {
		totalAge := maxAge

		age, ageOk, err := parseAge(headers)
		if err != nil {
			return time.Time{}, fmt.Errorf("parsing age: %w", err)
		} else if ageOk {
			totalAge -= age

			if totalAge < 0 {
				return time.Time{}, fmt.Errorf("negative age: %s-%s=%s", maxAge, age, totalAge)
			}
		}

		return now.Add(totalAge), nil
	}

	// no max-age, try Expires
	expires, expiresOk, err := parseExpires(headers)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing expires: %w", err)
	}

	if !expiresOk {
		return time.Time{}, errors.New("cache headers not present")
	}

	return expires, nil
}

// parseMaxAge extracts max-age or s-maxage from Cache-Control header
func parseMaxAge(header http.Header) (time.Duration, bool, error) {
	cch := header.Get("Cache-Control")
	if cch == "" {
		return 0, false, nil
	}

	var maxAgeStr string
	parts := strings.Split(cch, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)

		if strings.HasPrefix(part, cacheControlFieldMaxAge+"=") {
			maxAgeStr = strings.TrimPrefix(part, cacheControlFieldMaxAge+"=")
			break // prefer max-age when set
		}

		if strings.HasPrefix(part, cacheControlFieldSMaxAge+"=") {
			maxAgeStr = strings.TrimPrefix(part, cacheControlFieldSMaxAge+"=")
			continue // try finding max-age
		}
	}

	if maxAgeStr == "" {
		return 0, false, nil
	}

	maxAge, err := time.ParseDuration(maxAgeStr + "s")
	if err != nil {
		return 0, false, err
	}

	return maxAge, true, nil
}

// parseAge extracts age from Age header
func parseAge(header http.Header) (time.Duration, bool, error) {
	ageStr := header.Get(headerNameAge)
	if ageStr == "" {
		return 0, false, nil
	}

	age, err := time.ParseDuration(ageStr + "s")
	if err != nil {
		return 0, false, err
	}

	return age, true, nil
}

// parseExpires extracts Expires from Expires header
func parseExpires(header http.Header) (time.Time, bool, error) {
	expiresStr := header.Get(headerNameExpires)
	if expiresStr == "" {
		return time.Time{}, false, nil
	}

	expires, err := time.Parse(time.RFC1123, expiresStr)
	if err != nil {
		return time.Time{}, false, err
	}

	return expires, true, nil
}
