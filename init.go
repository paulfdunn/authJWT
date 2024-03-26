package authJWT

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"regexp"

	"github.com/paulfdunn/go-helper/databaseh/kvs"
	"github.com/paulfdunn/go-helper/logh"
	"github.com/paulfdunn/go-helper/osh/runtimeh"
)

// initializeKVS initializes KVS kvsAuth and kvsToken; these are the key
// value stores (KVS) for authentication and tokens.
func initializeKVS(dataSourcePath string) {
	var err error
	if kvsAuth, err = kvs.New(dataSourcePath, kvsAuthTable); err != nil {
		log.Fatalf("fatal: %s fatal: could not create New kvs, error: %v", runtimeh.SourceInfo(), err)
	}

	if kvsToken, err = kvs.New(dataSourcePath, kvsTokenTable); err != nil {
		log.Fatalf("fatal: %s fatal: could not create New kvs, error: %v", runtimeh.SourceInfo(), err)
	}
}

// passwordValidationLoad loads the default password validation rules.
func passwordValidationLoad() error {
	pwv := defaultPasswordValidation
	if config.PasswordValidation != nil {
		pwv = config.PasswordValidation
	}

	passwordValidation = make([]*regexp.Regexp, len(pwv))
	for i, v := range pwv {
		rg, err := regexp.Compile(v)
		if err != nil {
			log.Fatalf("fatal: %s password validation regex %s does not compile", runtimeh.SourceInfo(), v)
		}
		passwordValidation[i] = rg
	}

	return nil
}

// loadKeys loads the key for signing tokens.
func loadKeys(config Config) {
	var privKeyBytes, pubKeyBytes []byte
	var err error

	// For clients using an auth service, they will not have a JWTPrivateKeyPath
	if config.JWTPrivateKeyPath != "" {
		if privKeyBytes, err = os.ReadFile(config.JWTPrivateKeyPath); err != nil {
			log.Fatalf("fatal: %s could not load private key from path: %s, error: %v",
				runtimeh.SourceInfo(), config.JWTPrivateKeyPath, err)
		}
		block, _ := pem.Decode(privKeyBytes)
		var key any
		if key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			log.Fatalf("x509.ParsePKCS1PrivateKey error: %+v", err)
		}
		if k, ok := key.(*rsa.PrivateKey); ok {
			rsaPrivateKey = k
		}
	} else {
		lp(logh.Info, "No JWTPrivateKeyPath provided.")
	}

	if pubKeyBytes, err = os.ReadFile(config.JWTPublicKeyPath); err != nil {
		log.Fatalf("fatal: %s could not load public key from path: %s, error: %v",
			runtimeh.SourceInfo(), config.JWTPublicKeyPath, err)
	}

	block, _ := pem.Decode(pubKeyBytes)
	var key any
	if key, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		log.Fatalf("x509.ParsePKCS1PublicKey error: %+v", err)
	}
	if k, ok := key.(*rsa.PublicKey); ok {
		rsaPublicKey = k
	}
}
