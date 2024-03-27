// Package authJWT implements JWT authentication.
package authJWT

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/paulfdunn/go-helper/databaseh/kvs"
	"github.com/paulfdunn/go-helper/logh"
	"github.com/paulfdunn/go-helper/osh/runtimeh"

	"github.com/dgrijalva/jwt-go"
)

type Config struct {
	// AppName is used to populate the Issuer field of the Claims.
	AppName string
	// AuditLogName is the name of the logh logger for the audit log. Callers
	// must create their own logh loggers or output will go to STDOUT.
	AuditLogName string
	// DataSourcePath is the path to the SQLITE database used to persist auth and tokens.
	DataSourcePath string
	// CreateRequiresAuth - when true, requires an already authorized caller to create new
	// credentials. When false any caller can create their own auth.
	CreateRequiresAuth bool
	// JWTAuthRemoveInterval is the interval at which a GO routine runs, checks for expired
	// tokens, and invalidates all expired tokens. (A user can login from multiple devices
	// and can have more than one outstanding token.)
	JWTAuthRemoveInterval time.Duration
	// JWTAuthExpirationInterval is the duration for which a token is valid.
	JWTAuthExpirationInterval time.Duration
	// JWTPrivateKeyPath is the path to the private key used for signing the tokens.
	JWTPrivateKeyPath string
	// JWTPublicKeyPath is the path to the public key used for signing the tokens.
	JWTPublicKeyPath string
	// LogName is the name of the logh logger for general logging. Callers
	// must create their own logh loggers or output will go to STDOUT.
	LogName string
	// PasswordValidation is a slice of REGEX used for password validation. If nothing is
	// provided, defaultPasswordValidation is used.
	PasswordValidation []string
	// PathCreateOrUpdate is the final portion of the URL path for auth create or update.
	// If empty the default is used: /auth/createorupdate
	// Valid HTTP methods: http.MethodPost, http.MethodPut
	PathCreateOrUpdate string
	// PathDelete is the final portion of the URL path for delete. If empty the
	// default is used: /auth/delete
	// Valid HTTP methods: http.MethodDelete
	PathDelete string
	// PathInfo is the final portion of the URL path for info. If empty the
	// default is used: /auth/info
	// Valid HTTP methods: http.MethodGet
	PathInfo string
	// PathLogin is the final portion of the URL path for login. If empty the
	// default is used: /auth/login
	// Valid HTTP methods: http.MethodPut
	PathLogin string
	// PathLogout is the final portion of the URL path for logout. If empty the
	// default is used: /auth/logout
	// Valid HTTP methods: http.MethodDelete
	PathLogout string
	// PathLogoutAll is the final portion of the URL path for logout-all. If empty the
	// default is used: /auth/logout-all
	// Valid HTTP methods: http.MethodDelete
	PathLogoutAll string
	// PathRefresh is the final portion of the URL path for refresh. If empty the
	// default is used: /auth/refresh
	// Valid HTTP methods: http.MethodPost
	PathRefresh string
	// testing true bypasses loading keys.
	testing bool
}

// Credential is what is supplied by the HTTP request in order to authenticate.
type Credential struct {
	Email    *string
	Password *string
}

// CustomClaims are the Claims for the JWT token.
type CustomClaims struct {
	jwt.StandardClaims
	Email   string
	TokenID string
}

// Info is used to provide information back to the user.
type Info struct {
	OutstandingTokens int
}

// authentication is persisted data about a user and their authorization.
type authentication struct {
	Authorizations []string `json:",omitempty"`
	Email          *string  `json:",omitempty"`
	PasswordHash   []byte   `json:",omitempty"`
	Role           *string  `json:",omitempty"`
}

const (
	kvsAuthTable  = "authJWTAuth"
	kvsTokenTable = "authJWTToken"

	// bcrypt, used to hash the password, has a length limit of 72
	// https://pkg.go.dev/golang.org/x/crypto@v0.21.0/bcrypt#GenerateFromPassword
	passwordLengthLimit = 72
)

var (
	// config used by this package.
	config Config

	// default password validation: 8-32 characters, 1 lower case, 1 upper case, 1 special, 1 number.
	defaultPasswordValidation = []string{`^[\S]{8,32}$`, `[a-z]`, `[A-Z]`, `[!#$%'()*+,-.\\/:;=?@\[\]^_{|}~]`, `[0-9]`}

	lp  func(level logh.LoghLevel, v ...interface{})
	lpf func(level logh.LoghLevel, format string, v ...interface{})

	// The auth KVS stores authentications; one per Email.
	kvsAuth kvs.KVS
	// The token KVS stores the key (encoded as Email|TokenID) and the value is the
	// experation in Unix (seconds) time. A user may have more than one valid token.
	kvsToken           kvs.KVS
	passwordValidation []*regexp.Regexp

	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  *rsa.PublicKey
)

// Init initializes the package.
// createRequiresAuth == true requires auth creates to be from an already authenticated
// user. (Use for apps that require users be added by an admin.)
func Init(configIn Config, mux *http.ServeMux) {
	config = configIn

	lp = logh.Map[config.LogName].Println
	lpf = logh.Map[config.LogName].Printf

	if configIn.testing {
		var err error
		rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			log.Fatalf("could not generate keys for testing, error: %+v", err)
		}
		pubKey := rsaPrivateKey.Public().(*rsa.PublicKey)
		rsaPublicKey = pubKey
	} else {
		loadKeys(config)
	}

	// Applicaitons must provide a mux or register the handlers themselves.
	// For testing purposes, no mux is required.
	if mux != nil {
		// Set default auth paths where none was provided by the caller.
		if config.PathCreateOrUpdate == "" {
			config.PathCreateOrUpdate = "/auth/createorupdate"
		}
		if config.PathDelete == "" {
			config.PathDelete = "/auth/delete"
		}
		if config.PathInfo == "" {
			config.PathInfo = "/auth/info"
		}
		if config.PathLogin == "" {
			config.PathLogin = "/auth/login"
		}
		if config.PathLogout == "" {
			config.PathLogout = "/auth/logout"
		}
		if config.PathLogoutAll == "" {
			config.PathLogoutAll = "/auth/logout-all"
		}
		if config.PathRefresh == "" {
			config.PathRefresh = "/auth/refresh"
		}

		// Registering with the trailing slash means the naked path is redirected to this path.
		crpath := config.PathCreateOrUpdate + "/"
		if config.CreateRequiresAuth {
			mux.HandleFunc(crpath, HandlerFuncAuthJWTWrapper(handlerCreateOrUpdate))
		} else {
			mux.HandleFunc(crpath, handlerCreateOrUpdate)
		}
		lpf(logh.Info, "Registered handler: %s\n", crpath)
		dltpath := config.PathDelete + "/"
		mux.HandleFunc(dltpath, HandlerFuncAuthJWTWrapper(handlerDelete))
		lpf(logh.Info, "Registered handler: %s\n", dltpath)
		infpath := config.PathInfo + "/"
		mux.HandleFunc(infpath, HandlerFuncAuthJWTWrapper(handlerInfo))
		lpf(logh.Info, "Registered handler: %s\n", infpath)
		lipath := config.PathLogin + "/"
		mux.HandleFunc(lipath, handlerLogin)
		lpf(logh.Info, "Registered handler: %s\n", lipath)
		lopath := config.PathLogout + "/"
		mux.HandleFunc(lopath, HandlerFuncAuthJWTWrapper(handlerLogout))
		lpf(logh.Info, "Registered handler: %s\n", lopath)
		loapath := config.PathLogoutAll + "/"
		mux.HandleFunc(loapath, HandlerFuncAuthJWTWrapper(handlerLogoutAll))
		lpf(logh.Info, "Registered handler: %s\n", loapath)
		rfpath := config.PathRefresh + "/"
		mux.HandleFunc(rfpath, HandlerFuncAuthJWTWrapper(handlerRefresh))
		lpf(logh.Info, "Registered handler: %s\n", rfpath)
	}

	if config.DataSourcePath != "" {
		lpf(logh.Info, "authJWT running with DataSourcePath: %s", config.DataSourcePath)
		initializeKVS(config.DataSourcePath)
		passwordValidationLoad()
		removeExpiredTokens(config.JWTAuthRemoveInterval, config.JWTAuthExpirationInterval)
	} else {
		lp(logh.Info, "authJWT running without DataSourcePath - tokens can only be validated")
	}
}

// AuthCreate creates or updates an ID/authentication pair to kvsAuth. The scope of the function
// is public to allow apps to create auths directly, without going through the ReST API.
func (cred *Credential) AuthCreate() error {
	var err error
	var ph []byte
	if err := cred.validate(); err != nil {
		return err
	}
	if ph, err = passwordHash(*cred.Password); err != nil {
		return err
	}

	auth := authentication{Email: cred.Email, PasswordHash: ph}
	return authCreate(auth)
}

// Authenticated checks the request for a valid token and will return
// the users CustomClaims, or an error is auth fails. The token is verified to still
// exist in kvsToken; meaning the user has not logged out with that token. On any error the header
// is written with the appropriate http.Status; callers should not write header status.
func Authenticated(w http.ResponseWriter, r *http.Request) (*CustomClaims, error) {
	var claims *CustomClaims
	var err error
	if claims, err = AuthenticatedNoTokenInvalidation(w, r); err != nil {
		return nil, err
	}
	// Validate the token is in the token store; it may be invalidated by the user logging out,
	// or the token expiring.
	b, err := kvsToken.Get(claims.tokenKVSKey())
	if b == nil || err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, fmt.Errorf("%s token not valid", runtimeh.SourceInfo())
	}
	return claims, nil
}

// AuthenticatedNoTokenInvalidation checks the request for a valid token and will return
// the users CustomClaims, or an error is auth fails. The token is NOT verified to still
// exist in kvsToken; the token may have been invalidated but no error from this function
// means the token was valid at some point. This function should only be used by independent
// services that recieve tokens but don't have access to kvsToken. On any error the header
// is written with the appropriate http.Status; callers should not write header status.
func AuthenticatedNoTokenInvalidation(w http.ResponseWriter, r *http.Request) (*CustomClaims, error) {
	tokenString, err := tokenFromRequestHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, err
	}
	claims, err := parseClaims(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, err
	}
	return claims, nil
}

// tokenKVSKey creates a key for kvsToken using the Email and TokenID.
func (cc CustomClaims) tokenKVSKey() string {
	return cc.Email + "|" + cc.TokenID
}

// validate will validate the Credential, as well as trim space from members.
func (cred *Credential) validate() error {
	if cred.Email == nil || cred.Password == nil {
		return fmt.Errorf("%s either email or password were nil in credential", runtimeh.SourceInfo())
	}
	if len(*cred.Password) > passwordLengthLimit {
		return fmt.Errorf("%s password exceeds length limit of %d", runtimeh.SourceInfo(), passwordLengthLimit)
	}

	em := strings.TrimSpace(*cred.Email)
	pwd := strings.TrimSpace(*cred.Password)
	cred.Email = &em
	cred.Password = &pwd
	for _, v := range passwordValidation {
		if v.FindString(*cred.Password) == "" {
			return fmt.Errorf("%s password does not meet validation criteria %s", runtimeh.SourceInfo(), v.String())
		}
	}
	return nil
}

// authGet returns the authentication for the provided id. If the id is not in kvsAuth,
// there is no error, but the returned authentication object is empty.
func authGet(id string) (authentication, error) {
	auth := authentication{}
	if err := kvsAuth.Deserialize(id, &auth); err != nil {
		return authentication{}, runtimeh.SourceInfoError("authGet error", err)
	}
	return auth, nil
}

// authCreate sets an authentication in kvsAuth and will overwrite any existing
// value.
func authCreate(auth authentication) error {
	if err := kvsAuth.Serialize(*auth.Email, auth); err != nil {
		return runtimeh.SourceInfoError("serialize error", err)
	}
	return nil
}

// authTokenStringCreate stores a token in kvsToken, where the key is
// generated using tokenKVSKey() and the value is the claims.ExpiresAt.
func authTokenStringCreate(email string) (string, error) {
	tokenID, err := uniqueID(true)
	if err != nil {
		return "", runtimeh.SourceInfoError("authTokenStringCreate error", err)
	}
	claims := CustomClaims{
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(config.JWTAuthExpirationInterval).Unix(),
			Issuer:    config.AppName,
		},
		email,
		tokenID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, claims.ExpiresAt)
	if err != nil {
		runtimeh.SourceInfoError("binary.Write failed", err)
	}
	kvsToken.Set(claims.tokenKVSKey(), buf.Bytes())
	return token.SignedString(rsaPrivateKey)
}

// parseClaims parses a JWT token string (from the Authorization header)
// into a CustomClaims object.
func parseClaims(tokenString string) (*CustomClaims, error) {
	claimsIn := &CustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claimsIn,
		func(token *jwt.Token) (interface{}, error) {
			return rsaPublicKey, nil
		})
	if err != nil {
		return nil, runtimeh.SourceInfoError("ParseWithClaims error", err)
	}
	claimsOut := token.Claims.(*CustomClaims)
	if !token.Valid {
		return nil, fmt.Errorf("%s token not valid, token: %+v", runtimeh.SourceInfo(), *token)
	}

	return claimsOut, nil
}

// passwordHash hashes a password using bcrypt.
func passwordHash(pasword string) (hash []byte, err error) {
	if hash, err = bcrypt.GenerateFromPassword([]byte(pasword), bcrypt.DefaultCost); err != nil {
		return nil, runtimeh.SourceInfoError("could not hash password, error: %+v", err)
	}
	return hash, nil
}

// passwordVerifyHash verifies that the provided password hashes to the provided hash,
// or returns an error if they do not match.
func passwordVerifyHash(password string, hash []byte) error {
	return bcrypt.CompareHashAndPassword(hash, []byte(password))
}

// removeExpiredTokens is a go routine that continuously runs in the background
// and will remove tokens from kvsToken if expiresAt is more than expireInterval
// old.
// Calling with rate == 0 causes the go routine to return after running once.
func removeExpiredTokens(rate time.Duration, expireInterval time.Duration) {
	go func() {
		keys, err := kvsToken.Keys()
		if err == nil {
			for i := range keys {
				b, err := kvsToken.Get(keys[i])
				if err != nil {
					lpf(logh.Error, "getting token: %v\n", err)
					continue
				}

				buf := bytes.NewBuffer(b)
				var expiresAt int64
				err = binary.Read(buf, binary.LittleEndian, &expiresAt)
				if err != nil {
					lpf(logh.Error, "reading expiresAt: %v\n", err)
					continue
				}
				if time.Since(time.Unix(expiresAt, 0)) > expireInterval {
					_, err := kvsToken.Delete(keys[i])
					if err != nil {
						lpf(logh.Error, "deleting expired token: %v\n", err)
						continue
					}
				}

			}
		} else {
			lpf(logh.Error, "getting keys: %v\n", err)
		}

		if rate == 0 {
			return
		}

		time.Sleep(rate)
	}()
}

// tokenFromRequestHeader returns the data in the Authorization header.
func tokenFromRequestHeader(r *http.Request) (string, error) {
	var tokenHeader []string
	var ok bool
	if tokenHeader, ok = r.Header["Authorization"]; !ok {
		return "", fmt.Errorf("%s no Authorization header provided", runtimeh.SourceInfo())
	}

	return regexp.MustCompile(`[bB]earer|\s*`).ReplaceAllString(tokenHeader[0], ""), nil
}

// uniqueID is used to generate 16 byte (32 character) ID's; as a UUID (includeHuphens) or
// hex string. The return value is a hex string formatted in ASCII.
// 16 bytes = 128 bits, 2^128 = 3.4028237e+38
func uniqueID(includeHyphens bool) (id string, err error) {
	idBin := make([]byte, 16)
	_, err = rand.Read(idBin)
	if err != nil {
		err := runtimeh.SourceInfoError("creating unique binary ID, error: %+v", err)
		fmt.Printf("%+v\n", err)
		return "", err
	}

	if includeHyphens {
		return fmt.Sprintf("%x-%x-%x-%x-%x", idBin[0:4], idBin[4:6], idBin[6:8], idBin[8:10], idBin[10:]), err
	}

	return fmt.Sprintf("%x", idBin[:]), err
}

// userTokens gets a count of tokens in kvsToken for the specified email. If
// remove == true, all tokens are removed and the count is the number of removed
// tokens.
func userTokens(email string, remove bool) (int, error) {
	keys, err := kvsToken.Keys()
	if err != nil {
		lpf(logh.Error, "getting keys: %v\n", err)
		return 0, err
	}

	count := 0
	for i := range keys {
		_, err := kvsToken.Get(keys[i])
		if err != nil {
			lpf(logh.Error, "getting token: %v\n", err)
			return count, err
		}

		if strings.HasPrefix(keys[i], email) {
			if remove {
				kvsToken.Delete(keys[i])
			}
			count++
		}
	}

	return count, nil
}
