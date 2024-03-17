// Package authJWT implements JWT authentication.
//
// Callers will need to wrap their handlers using HandlerFuncAuthJWTWrapper;
// see the test TestHandlerFuncAuthJWTWrapper for an example.
// The provided wrappers log all DELETE/POST/PUT calls to logh.Map[*cnfg.AuditLogName].
// Tokens are stored locally to allow invalidating a token for logout, or
// invalidating all tokens for a user.
//
// Use only HTTPS to prevent tokens being stolen in-flight; I.E. public wi-fi.
// Callers should not store the tokens. Use the token for the session only; the user
// can save their credentials via their browser, if they chose, to make logging
// in easier. Do also allow your users access to logout-all, as well as to the
// number of tokens available for their ID.
package authJWT

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
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
	AppName                string
	AuditLogName           string
	DataSourceName         string
	CreateRequiresAuth     bool
	JWTAuthRemoveInterval  time.Duration
	JWTAuthTimeoutInterval time.Duration
	JWTKeyFilepath         string
	LogName                string
	PasswordValidation     []string
	PathCreate             string
	PathDelete             string
	PathInfo               string
	PathLogin              string
	PathLogout             string
	PathLogoutAll          string
	PathRefresh            string
}

// authentication is persisted data about a user and their authorization.
type authentication struct {
	Authorizations []string `json:",omitempty"`
	Email          *string  `json:",omitempty"`
	PasswordHash   []byte   `json:",omitempty"`
	Role           *string  `json:",omitempty"`
}

// Credential is what is supplied by the HTTP request in order to authenticate.
type Credential struct {
	Email    *string
	Password *string
}

type CustomClaims struct {
	jwt.StandardClaims
	Email   string
	TokenID string
}

type Info struct {
	OutstandingTokens int
}

const (
	authJWTAuthKVS = "authJWTAuth"
	authTokenKVS   = "authJWTToken"
)

var (
	config Config

	// lp     func(level logh.LoghLevel, v ...interface{})
	lpf func(level logh.LoghLevel, format string, v ...interface{})

	// The auth KVS stores authentications; one per Email.
	kvsAuth kvs.KVS
	// The token KVS stores the key (encoded as Email|TokenID) and the value is the
	// experation in Unix (seconds) time. A user may have more than one valid token.
	kvsToken           kvs.KVS
	passwordValidation []*regexp.Regexp

	tokenKey []byte
)

// Init initializes the package.
// createRequiresAuth == true requires auth creates to be from an already authenticated
// user. (Use for apps that require uses be added by an admin.)
func Init(configIn Config, mux *http.ServeMux) {
	config = configIn

	tokenKeyLoad(config.JWTKeyFilepath)

	// Registering with the trailing slash means the naked path is redirected to this path.
	crpath := config.PathCreate + "/"
	if config.CreateRequiresAuth {
		mux.HandleFunc(crpath, HandlerFuncAuthJWTWrapper(handlerCreate))
	} else {
		mux.HandleFunc(crpath, handlerCreate)
	}

	// lp = logh.Map[config.LogName].Println
	lpf = logh.Map[config.LogName].Printf

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

	initializeKVS(config.DataSourceName)

	passwordValidationLoad()

	removeExpiredTokens(config.JWTAuthRemoveInterval, config.JWTAuthTimeoutInterval)
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
// the users CustomClaims.
func Authenticated(w http.ResponseWriter, r *http.Request) (*CustomClaims, error) {
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
	b, err := kvsToken.Get(claims.tokenKVSKey())
	if b == nil || err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, fmt.Errorf("%s token not valid", runtimeh.SourceInfo())
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
			ExpiresAt: time.Now().Add(config.JWTAuthTimeoutInterval).Unix(),
			Issuer:    config.AppName,
		},
		email,
		tokenID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, claims.ExpiresAt)
	if err != nil {
		runtimeh.SourceInfoError("binary.Write failed", err)
	}
	kvsToken.Set(claims.tokenKVSKey(), buf.Bytes())
	return token.SignedString(tokenKey)
}

// parseClaims parses a JWT token string (from the Authorization header)
// into a CustomClaims object.
func parseClaims(tokenString string) (*CustomClaims, error) {
	claimsIn := &CustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claimsIn,
		func(token *jwt.Token) (interface{}, error) {
			return tokenKey, nil
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
