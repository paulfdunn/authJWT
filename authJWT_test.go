package authJWT

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/paulfdunn/go-helper/logh"
	"github.com/paulfdunn/go-helper/osh/runtimeh"
)

var (
	dataSourcePath string
)

func init() {
	t := testing.T{}
	testDir := t.TempDir()
	dataSourcePath = filepath.Join(testDir, "test.db")

	// testSetup only to initialize config
	testSetup()
	// lp = logh.Map[config.LogName].Println
	lpf = logh.Map[config.LogName].Printf
}

// TestAuthCreateGetDelete tests internal functions to create, get, and delete auth.
func TestAuthCreateGetDelete(t *testing.T) {
	testSetup()

	em := "someone@somewhere.com"
	ps := "P@ss1234"
	cred := Credential{Email: &em, Password: &ps}

	auth, err := authGet(em)
	if auth.Email != nil {
		t.Errorf("authGet before create did not produce nil auth: %v", err)
		return
	}

	err = cred.AuthCreate()
	if err != nil {
		t.Errorf("AuthCreate error: %v", err)
		return
	}

	auth, err = authGet(em)
	if err != nil || *auth.Email != em || passwordVerifyHash(ps, auth.PasswordHash) != nil {
		t.Errorf("authGet error: %v", err)
		return
	}

	count, err := authDelete(em)
	if count != 1 || err != nil {
		t.Errorf("authDelete count: %d, error: %v", count, err)
		return
	}

	count, err = authDelete(em)
	if count != 0 || err != nil {
		t.Errorf("authDelete count: %d, error: %v", count, err)
		return
	}
}

// TestAuthTokenCreate tests creating a token for a given auth.
func TestAuthTokenCreate(t *testing.T) {
	testSetup()

	tokenString, err := authTokenStringCreate("testEmail")
	if err != nil {
		t.Errorf("creating auth token, error: %v", err)
		return
	}
	// fmt.Printf("tokenString: %s\n", tokenString)

	claimsIn := &CustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claimsIn,
		func(token *jwt.Token) (interface{}, error) {
			return rsaPublicKey, nil
		})
	if err != nil {
		t.Errorf("ParseWithClaims, error: %v", err)
		return
	}

	var ok bool
	// uncomment print and add first parameter claimsOut to token.Claims call for debugging.
	// var claimsOut *CustomClaims
	if _, ok = token.Claims.(*CustomClaims); !ok || !token.Valid {
		t.Error("token is not valid or type assertion failed.")
		return
	}
	// fmt.Printf("claims %+v\n", *claimsOut)
}

func TestRemoveExpiredTokens(t *testing.T) {
	testSetup()

	durations := []time.Duration{time.Duration(0), time.Duration(500) * time.Millisecond}
	removeDuration := time.Duration(0) * time.Millisecond
	for _, v := range durations {
		config.JWTAuthExpirationInterval = v
		_, credBytes, err := createAuth(t, nil)
		if err != nil {
			return
		}

		tokenBytes, _, err := login(t, credBytes)
		if err != nil {
			return
		}

		claimsOut, err := parseClaims(string(tokenBytes))
		if err != nil {
			t.Errorf("parseClaims error: %v", err)
			return
		}
		kvsBytes, err := kvsToken.Get(claimsOut.tokenKVSKey())
		if kvsBytes == nil || err != nil {
			t.Errorf("kvsToken.Get error: %v", err)
			return
		}

		removeExpiredTokens(removeDuration, removeDuration)
		time.Sleep(removeDuration * 2)
		kvsBytes, _ = kvsToken.Get(claimsOut.tokenKVSKey())
		if kvsBytes != nil && v < removeDuration {
			t.Errorf("kvsToken.Get returned bytes and should not have")
			return
		} else {
			// fmt.Printf("TestRemoveExpiredTokens negative test passed\n")
		}
	}
}

func TestValidateNegative(t *testing.T) {
	testSetup()

	em := "someone@somewhere.com"
	pws := []string{"  p@ss123", "  Pass123  ", " P@ssabc  "}
	for _, pw := range pws {
		cred := Credential{Email: &em, Password: &pw}
		err := cred.AuthCreate()
		if err == nil {
			t.Errorf("AuthCreate did not have error on password: %s", pw)
			return
		}
	}
}

func TestValidatePositive(t *testing.T) {
	testSetup()

	em := "someone@somewhere.com"
	pws := []string{" P@ss1234 ", " p!Ss1234 ", " p#sS1234567890123456789012344456 "}
	for _, pw := range pws {
		cred := Credential{Email: &em, Password: &pw}
		err := cred.AuthCreate()
		if err != nil {
			t.Errorf("AuthCreate error on password: %s, err: %v", pw, err)
			return
		}
	}
}

func TestUniqueID(t *testing.T) {
	id, err := uniqueID(false)
	m := regexp.MustCompile("[0-9a-f]{8}[0-9a-f]{4}[0-9a-f]{4}[0-9a-f]{4}[0-9a-f]{12}").MatchString(id)
	// fmt.Printf("uniqueID:%s\n", id)
	if !m || err != nil {
		t.Errorf("id not right format, id: %s", id)
	}

	id, err = uniqueID(true)
	m = regexp.MustCompile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").MatchString(id)
	// fmt.Printf("uniqueID:%s\n", id)
	if !m || err != nil {
		t.Errorf("id not right format, id: %s", id)
	}
}

// authDelete removes an ID/authentication pair from the KVS.
// Returns the count, which is zero (and no error) if the id did not exist.
func authDelete(id string) (int64, error) {
	c, err := kvsAuth.Delete(id)
	return c, runtimeh.SourceInfoError("authDelete error", err)
}

// createAuth creates an entry in kvsAuth
func createAuth(t *testing.T, email *string) (string, []byte, error) {
	// create auth (user)
	em := "someone@auth.com"
	if email != nil {
		em = *email
	}
	ps := "P@ssword1234"
	cred := &Credential{Email: &em, Password: &ps}
	cred.AuthCreate()
	credBytes, err := json.Marshal(cred)
	if err != nil {
		t.Errorf("marshal error: %v", err)
		return "", nil, err
	}
	return em, credBytes, nil
}

// login using the provided credentials and return a token and claims.
func login(t *testing.T, credBytes []byte) ([]byte, *CustomClaims, error) {
	// login
	testServerLogin := httptest.NewServer(http.HandlerFunc(handlerLogin))
	defer testServerLogin.Close()
	client := http.Client{}
	req, err := http.NewRequest(http.MethodPut, testServerLogin.URL, bytes.NewBuffer(credBytes))
	if err != nil {
		t.Errorf("NewRequest error: %v", err)
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("POST error: %v", err)
		return nil, nil, err
	}
	if resp.StatusCode != 200 {
		t.Errorf("status code: %d", resp.StatusCode)
		return nil, nil, err
	}
	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("ReadAll error: %v", err)
		return nil, nil, err
	}
	resp.Body.Close()
	// fmt.Printf("tokenBytes :%s\n", string(tokenBytes))
	claimsOut, err := parseClaims(string(tokenBytes))
	if err != nil {
		t.Errorf("parseClaims error: %v", err)
		return nil, nil, err
	}
	return tokenBytes, claimsOut, err
}

func testSetup() {
	os.Remove(dataSourcePath)

	config = Config{AppName: "auth", AuditLogName: "auth.audit", LogName: "auth",
		JWTAuthExpirationInterval: time.Minute * 15,
		JWTPrivateKeyPath:         "./key/jwt.rsa.private",
		JWTPublicKeyPath:          "./key/jwt.rsa.public",
	}
	config.DataSourcePath = dataSourcePath
	Init(config, nil)
}
