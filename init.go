package authJWT

import (
	"log"
	"os"
	"regexp"

	"github.com/paulfdunn/go-helper/databaseh/kvs"
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

// tokenKeyLoad loads the key for signing tokens.
func tokenKeyLoad(tokenKeyFilepath string) {
	var err error
	if tokenKey, err = os.ReadFile(tokenKeyFilepath); err != nil {
		log.Fatalf("fatal: %s could not load tokenKey from path: %s, error: %v", runtimeh.SourceInfo(), tokenKeyFilepath, err)
	}
}
