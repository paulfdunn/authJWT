// Package authJWT implements JWT authentication.
// This is a simple implementation, using a single authentication token with
// an expiration. Callers will need to wrap their handlers using HandlerFuncAuthJWTWrapper;
// see the test TestHandlerFuncAuthJWTWrapper for an example.
// The provided wrappers log all DELETE/POST/PUT calls to logh.Map[*cnfg.AuditLogName].
// Tokens are stored locally to allow invalidating the token for logout.
// Use only HTTPS to prevent tokens being stolen in-flight; I.E. public wi-fi.

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

	"github.com/dgrijalva/jwt-go"
	"github.com/paulfdunn/db/kvs"
	"github.com/paulfdunn/logh"
	"github.com/paulfdunn/osh/runtimeh"
	"golang.org/x/crypto/bcrypt"
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

const (
	createPath  = "/auth/create"
	deletePath  = "/auth/delete"
	loginPath   = "/auth/login"
	logoutPath  = "/auth/logout"
	refreshPath = "/auth/refresh"

	authJWTAuthKVS = "authJWTAuth"
	authTokenKVS   = "authJWTToken"
)

var (
	config  Config
	kviAuth kvs.KVS
	// The token KVS stores the ID and the expire time.
	kviToken           kvs.KVS
	passwordValidation []*regexp.Regexp

	tokenKey []byte
)

// Init initializes the package.
// createRequiresAuth == true requires auth creates to be from an already authenticated
// user. (Use for apps that require uses be added by an admin.)
func Init(configIn Config) {
	config = configIn

	tokenKeyLoad(config.JWTKeyFilepath)

	// Registering with the trailing slash means the naked path is redirected to this path.
	crpath := createPath + "/"
	if config.CreateRequiresAuth {
		http.HandleFunc(crpath, HandlerFuncAuthJWTWrapper(handlerCreate))
	} else {
		http.HandleFunc(crpath, handlerCreate)
	}
	logh.Map[config.LogName].Printf(logh.Info, "Registered handler: %s\n", crpath)
	dltpath := deletePath + "/"
	http.HandleFunc(dltpath, HandlerFuncAuthJWTWrapper(handlerDelete))
	logh.Map[config.LogName].Printf(logh.Info, "Registered handler: %s\n", dltpath)
	lipath := loginPath + "/"
	http.HandleFunc(lipath, handlerLogin)
	logh.Map[config.LogName].Printf(logh.Info, "Registered handler: %s\n", lipath)
	lopath := logoutPath + "/"
	http.HandleFunc(lopath, HandlerFuncAuthJWTWrapper(handlerLogout))
	logh.Map[config.LogName].Printf(logh.Info, "Registered handler: %s\n", lopath)
	rfpath := refreshPath + "/"
	http.HandleFunc(rfpath, HandlerFuncAuthJWTWrapper(handlerRefresh))
	logh.Map[config.LogName].Printf(logh.Info, "Registered handler: %s\n", rfpath)

	initializeKVS(config.DataSourceName)

	passwordValidationLoad()

	removeExpiredTokens(config.JWTAuthRemoveInterval, config.JWTAuthTimeoutInterval)
}

// AuthCreate adds an ID/authentication pair to the KVS. Public to allow apps to
// create auths directly, without going through the ReST API.
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
	return authUpdate(auth)
}

// Authenticated checks the request for a valid token
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
	b, err := kviToken.Get(claims.TokenID)
	if b == nil || err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, fmt.Errorf("%s token not valid", runtimeh.SourceInfo())
	}
	return claims, nil
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

func authGet(id string) (authentication, error) {
	auth := authentication{}
	if err := kviAuth.Deserialize(id, &auth); err != nil {
		return authentication{}, runtimeh.SourceInfoError("authGet error", err)
	}
	return auth, nil
}

func authUpdate(auth authentication) error {
	if err := kviAuth.Serialize(*auth.Email, auth); err != nil {
		return runtimeh.SourceInfoError("serialize error", err)
	}
	return nil
}

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
	kviToken.Set(tokenID, buf.Bytes())
	return token.SignedString(tokenKey)
}

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

func passwordHash(pasword string) (hash []byte, err error) {
	if hash, err = bcrypt.GenerateFromPassword([]byte(pasword), bcrypt.DefaultCost); err != nil {
		return nil, runtimeh.SourceInfoError("could not hash password, error: %+v", err)
	}
	return hash, nil
}

func passwordVerifyHash(password string, hash []byte) error {
	return bcrypt.CompareHashAndPassword(hash, []byte(password))
}

func removeExpiredTokens(rate time.Duration, expireInterval time.Duration) {
	go func() {
		keys, err := kviToken.Keys()
		if err == nil {
			for i := range keys {
				b, err := kviToken.Get(keys[i])
				if err != nil {
					logh.Map[config.LogName].Printf(logh.Error, "getting token: %v\n", err)
					continue
				}

				buf := bytes.NewBuffer(b)
				var expiresAt int64
				err = binary.Read(buf, binary.LittleEndian, expiresAt)
				if err != nil {
					logh.Map[config.LogName].Printf(logh.Error, "reading exipresAt: %v\n", err)
					continue
				}
				if time.Since(time.Unix(expiresAt, 0)) > expireInterval {
					_, err := kviToken.Delete(keys[i])
					if err != nil {
						logh.Map[config.LogName].Printf(logh.Error, "deleting expired token: %v\n", err)
						continue
					}
				}

			}
		} else {
			logh.Map[config.LogName].Printf(logh.Error, "getting keys: %v\n", err)
		}

		time.Sleep(rate)
	}()
}

func tokenFromRequestHeader(r *http.Request) (string, error) {
	var tokenHeader []string
	var ok bool
	if tokenHeader, ok = r.Header["Authorization"]; !ok {
		return "", fmt.Errorf("%s no Authorization header provided", runtimeh.SourceInfo())
	}

	return regexp.MustCompile(`[bB]earer|\s*`).ReplaceAllString(tokenHeader[0], ""), nil
}

// uniqueID is used to generate 16 byte (32 character) ID's; as a UUID (includeHuphens) or
// hex string. Note these are hex strings; they do not include all alphanumeric characters.
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
