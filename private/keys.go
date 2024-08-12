package private

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dimovnike/go-jwksclient/keyfiles"

	"github.com/lestrrat-go/jwx/jwk"
)

func (kl *Keyloader) LoadPrivateKey(srcPrivateKey []byte) (jwk.Key, error) {
	kl.config.Logger.Debug().Msgf("loading jwt private key (%d bytes)", len(srcPrivateKey))

	var err error

	// load private key
	pkPem, _ := pem.Decode(srcPrivateKey)

	if pkPem == nil {
		return nil, fmt.Errorf("EC private key not in PEM format")
	}

	if pkPem.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("EC private key PEM wrong format: %s", pkPem.Type)
	}

	var parsedKey interface{}

	if parsedKey, err = x509.ParseECPrivateKey(pkPem.Bytes); err != nil {
		return nil, fmt.Errorf("parse EC private key: %w", err)
	}

	var privateKey *ecdsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unable to cast EC private key")
	}

	// create sign JWK
	jwkPrivateKey, err := jwk.New(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create sign JWK: %w", err)
	}

	return jwkPrivateKey, nil
}

func (kl *Keyloader) LoadPrivateKeyFromFile(privateKeyFile string) (jwk.Key, error) {
	pkBuf, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read private key file %s: %w", privateKeyFile, err)
	}

	return kl.LoadPrivateKey(pkBuf)
}

func (kl *Keyloader) loadKeys(dir string) (jwk.Set, error) {
	fileMetadata, skipped, err := keyfiles.GetFileMetadata(dir)
	if err != nil {
		return nil, fmt.Errorf("getting file metadata: %w", err)
	}

	keySet := jwk.NewSet()

	loaded := map[string]string{}

	for _, f := range fileMetadata {
		fullPath := filepath.Join(dir, f.Name)

		key, err := kl.LoadPrivateKeyFromFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("loading key from %s: %w", fullPath, err)
		}

		keyId := f.Name
		if strings.HasSuffix(strings.ToLower(keyId), ".priv") {
			keyId = keyId[:len(keyId)-5]
		}

		key.Set(jwk.KeyIDKey, keyId)
		key.Set(jwk.KeyUsageKey, jwk.ForSignature)

		added := keySet.Add(key)

		if !added {
			kl.config.Logger.Warn().Str("filename", f.Name).Str("keyId", keyId).Msg("key already loaded")
		}

		loaded[f.Name] = keyId
	}

	if len(skipped) > 0 {
		kl.config.Logger.Info().Interface("skipped", skipped).Interface("loaded", loaded).Msg("loaded private keys")
	}

	return keySet, nil
}
