package authJWT

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/paulfdunn/osh/runtimeh"
)

var (
	dataSourceName string
)

func init() {
	t := testing.T{}
	testDir := t.TempDir()
	dataSourceName = filepath.Join(testDir, "test.db")
}

func TestAuthCreateGetDelete(t *testing.T) {
	testSetup(t)

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

func TestHandlerFuncAuthJWTWrapper(t *testing.T) {
	testSetup(t)

	// handler does not require auth
	testServerNoWrap := httptest.NewServer(http.HandlerFunc(handlerTest))
	resp, _ := http.Get(testServerNoWrap.URL)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("HandlerFuncAuthJWTWrapper method did not return proper status: %d", resp.StatusCode)
		return
	}
	testServerNoWrap.Close()

	// handler DOES require auth, but none provided.
	testServerWrapped := httptest.NewServer(http.HandlerFunc(HandlerFuncAuthJWTWrapper(handlerTest)))
	resp, _ = http.Get(testServerWrapped.URL)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("HandlerFuncAuthJWTWrapper method did not return proper status: %d", resp.StatusCode)
		return
	}

	// handler still requires auth, provide token.
	_, credBytes, err := createAuth(t, nil)
	if err != nil {
		return
	}
	tokenBytes, _, err := login(t, credBytes)
	if err != nil {
		return
	}
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodDelete, testServerWrapped.URL, nil)
	if err != nil {
		t.Errorf("NewRequest error: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+string(tokenBytes))
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Errorf("HandlerFuncAuthJWTWrapper did not return proper status: %d", resp.StatusCode)
		return
	}

	testServerWrapped.Close()
}

func TestAuthTokenCreate(t *testing.T) {
	testSetup(t)

	tokenString, err := authTokenStringCreate("testEmail")
	if err != nil {
		t.Errorf("creating auth token, error: %v", err)
		return
	}
	// fmt.Printf("tokenString: %s\n", tokenString)

	claimsIn := &CustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claimsIn,
		func(token *jwt.Token) (interface{}, error) {
			return tokenKey, nil
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

func TestHandlerCreate(t *testing.T) {
	testSetup(t)

	testServer := httptest.NewServer(http.HandlerFunc(handlerCreate))
	em := "newAuth@auth.com"
	pwd := "P@ass!234"
	cred := Credential{Email: &em, Password: &pwd}
	b, err := json.Marshal(cred)
	if err != nil {
		t.Errorf("TestHandlerCreate marshal error: %v", err)
		return
	}

	// negative test - GET not allowed.
	resp, _ := http.Get(testServer.URL)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("invalid method did not return proper status: %d", resp.StatusCode)
		return
	}

	resp, err = http.Post(testServer.URL, "application/json", bytes.NewBuffer(b))
	if err != nil {
		t.Errorf("TestHandlerCreate error: %v", err)
		return
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("TestHandlerCreate did not return proper status: %d", resp.StatusCode)
		return
	}

	b, err = kviAuth.Get(em)
	if err != nil {
		t.Errorf("Get kviAuth error: %v", err)
		return
	}
	// No error, auth was created.

	// negative test - should error on creating existing auth
	resp, err = http.Post(testServer.URL, "application/json", bytes.NewBuffer(b))
	if err != nil {
		t.Errorf("TestHandlerCreate error: %v", err)
		return
	}
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("TestHandlerCreate did not return proper status: %d", resp.StatusCode)
		return
	}

}

func TestHandlerDelete(t *testing.T) {
	testSetup(t)

	em, credBytes, err := createAuth(t, nil)
	if err != nil {
		return
	}

	tokenBytes, _, err := login(t, credBytes)
	if err != nil {
		return
	}

	testServer := httptest.NewServer(http.HandlerFunc(HandlerFuncAuthJWTWrapper(handlerDelete)))
	defer testServer.Close()
	client := http.Client{}

	// negative test - GET not allowed.
	resp, _ := http.Get(testServer.URL)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("invalid method did not return proper status: %d", resp.StatusCode)
		return
	}

	// negative test - should fail without token in request
	req, err := http.NewRequest(http.MethodDelete, testServer.URL, nil)
	if err != nil {
		t.Errorf("TestHandlerDelete error: %v", err)
		return
	}
	// req.Header.Set("Authorization", "Bearer "+string(tokenBytes))
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("TestHandlerDelete did not return proper status: %d", resp.StatusCode)
		return
	}

	// positive test
	req, err = http.NewRequest(http.MethodDelete, testServer.URL, nil)
	if err != nil {
		t.Errorf("TestHandlerDelete error: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+string(tokenBytes))
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Errorf("TestHandlerDelete did not return proper status: %d", resp.StatusCode)
		return
	}

	b, err := kviAuth.Get(em)
	if err != nil || b != nil {
		t.Error("Get kviAuth had no error, or returned bytes, and should not have")
		return
	}

}

func TestHandlerInfo(t *testing.T) {
	testSetup(t)

	// Just put a random user in the DB
	_, credBytes, err := createAuth(t, nil)
	if err != nil {
		return
	}

	_, _, err = login(t, credBytes)
	if err != nil {
		return
	}

	// Then add three tokens for the same user.
	manyLogins := 3
	userManyLogins := "many@login.com"
	var tokenBytes []byte
	for i := 0; i < manyLogins; i++ {
		_, credBytes, err := createAuth(t, &userManyLogins)
		if err != nil {
			return
		}

		tokenBytes, _, err = login(t, credBytes)
		if err != nil {
			return
		}
	}

	testServer := httptest.NewServer(http.HandlerFunc(HandlerFuncAuthJWTWrapper(handlerInfo)))
	defer testServer.Close()
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
	if err != nil {
		t.Errorf("NewRequest error: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+string(tokenBytes))
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("client.Do error: %v", err)
		return
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("reading body error: %v", err)
		return
	}
	info := Info{}
	err = json.Unmarshal(b, &info)
	if err != nil {
		t.Errorf("unmarshal error: %v", err)
		return
	}
	fmt.Printf("%+v\n", info)
	if err != nil {
		t.Errorf("POST error: %v", err)
		return
	}
	if info.OutstandingTokens != 3 {
		t.Errorf("Wrong number of OutstandingTokens")
	}
}
func TestHandlerLogin(t *testing.T) {
	testSetup(t)

	// 0 - positive test, 1 - negative test; login with no auth created.
	// create credentials, POST it, verify the returned body can be parsed to a token.
	for i := 0; i <= 1; i++ {

		// For loop==1 get credentials but delete the auth.
		tem := fmt.Sprintf("testLogin@auth.com.%d", i)
		_, credBytes, err := createAuth(t, &tem)
		if err != nil {
			return
		}
		if i == 1 {
			authDelete(tem)
		}

		// tokenBytes, claims, err := login(t, credBytes)
		// if err != nil {
		// 	return
		// }

		testServer := httptest.NewServer(http.HandlerFunc(handlerLogin))
		defer testServer.Close()

		// negative test - GET not allowed.
		resp, _ := http.Get(testServer.URL)
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("invalid method did not return proper status: %d", resp.StatusCode)
			return
		}

		// negative test - POST with no body.
		client := &http.Client{}
		req, err := http.NewRequest(http.MethodPut, testServer.URL, nil)
		if err != nil {
			t.Errorf("NewRequest error: %v", err)
			return
		}
		resp, err = client.Do(req)
		if err != nil || resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("error or Post with no body did not return proper status: %d", resp.StatusCode)
			return
		}

		expectedExpireTime := time.Now().Add(config.JWTAuthTimeoutInterval).Unix()
		req, err = http.NewRequest(http.MethodPut, testServer.URL, bytes.NewBuffer(credBytes))
		if err != nil {
			t.Errorf("NewRequest error: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err = client.Do(req)
		if err != nil {
			t.Errorf("POST error: %v", err)
			return
		}
		if i == 0 && resp.StatusCode != 200 {
			t.Errorf("status code: %d", resp.StatusCode)
			return
		} else if i == 1 && resp.StatusCode != 401 {
			t.Errorf("status code: %d", resp.StatusCode)
			return
		}

		if i > 0 {
			continue
		}

		tokenBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("ReadAll error: %v", err)
		}
		resp.Body.Close()
		// fmt.Printf("tokenBytes :%s\n", string(tokenBytes))
		claimsOut, err := parseClaims(string(tokenBytes))
		expireDiff := expectedExpireTime - claimsOut.ExpiresAt
		// fmt.Printf("expireDiff: %d\n", expireDiff)
		if err != nil || claimsOut.Email != tem || expireDiff < -5 || expireDiff > 5 {
			t.Errorf("token not valid and should be, error: %+v", err)
			return
		}
	}
}

func TestHandlerLogout(t *testing.T) {
	testSetup(t)

	_, credBytes, err := createAuth(t, nil)
	if err != nil {
		return
	}

	tokenBytes, claims, err := login(t, credBytes)
	if err != nil {
		return
	}

	// logout and verify token deleted from kviToken
	testServer := httptest.NewServer(http.HandlerFunc(HandlerFuncAuthJWTWrapper(handlerLogout)))
	defer testServer.Close()
	client := &http.Client{}
	// negative test with invalid method
	req, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
	if err != nil {
		t.Errorf("NewRequest error: %v", err)
		return
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Logout GET did not return proper status: %d", resp.StatusCode)
		return
	}
	// negative test with  no credentials
	req, err = http.NewRequest(http.MethodDelete, testServer.URL, nil)
	if err != nil {
		t.Errorf("NewRequest error: %v", err)
	}
	// req.Header.Set("Authorization", "Bearer "+string(tokenBytes))
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Logout did not return proper status: %d", resp.StatusCode)
		return
	}
	// positive test
	req, err = http.NewRequest(http.MethodDelete, testServer.URL, nil)
	if err != nil {
		t.Errorf("NewRequest error: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+string(tokenBytes))
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Errorf("Logout did not return proper status: %d", resp.StatusCode)
		return
	} else if resp == nil || (resp != nil && resp.StatusCode != http.StatusNoContent) {
		t.Errorf("Logout did not return proper status or was nil: %d", resp.StatusCode)
		return
	}
	b, err := kviToken.Get(claims.tokenKVSKey())
	if !(b == nil && err == nil) {
		t.Error("TokenID not deleted.")
		return
	}
}

func TestHandlerLogoutAll(t *testing.T) {
	testSetup(t)

	// Just put a random user in the DB
	_, credBytes, err := createAuth(t, nil)
	if err != nil {
		return
	}

	_, _, err = login(t, credBytes)
	if err != nil {
		return
	}

	// Then add three tokens for the same user.
	manyLogins := 3
	userManyLogins := "many@login.com"
	var tokenBytes []byte
	for i := 0; i < manyLogins; i++ {
		_, credBytes, err := createAuth(t, &userManyLogins)
		if err != nil {
			return
		}

		tokenBytes, _, err = login(t, credBytes)
		if err != nil {
			return
		}
	}

	testServer := httptest.NewServer(http.HandlerFunc(HandlerFuncAuthJWTWrapper(handlerLogoutAll)))
	defer testServer.Close()
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodDelete, testServer.URL, nil)
	if err != nil {
		t.Errorf("NewRequest error: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+string(tokenBytes))
	_, err = client.Do(req)
	if err != nil {
		t.Errorf("POST error: %v", err)
		return
	}

	// This can be used to test the function directly.
	// r, err := removeUserTokens(userManyLogins)
	// if r != manyLogins || err != nil {
	// 	t.Errorf("removeUserTokens returned error or wrong number of key removals")
	// 	return
	// }

	k, err := kviToken.Keys()
	if len(k) != 1 || err != nil {
		t.Errorf("There should still be one user token.")
	}
}

func TestHandlerRefresh(t *testing.T) {
	testSetup(t)

	_, credBytes, err := createAuth(t, nil)
	if err != nil {
		return
	}

	tokenBytesLogin, _, err := login(t, credBytes)
	if err != nil {
		return
	}

	testServer := httptest.NewServer(http.HandlerFunc(HandlerFuncAuthJWTWrapper(handlerRefresh)))
	defer testServer.Close()
	client := &http.Client{}

	expectedExpireTime := time.Now().Add(config.JWTAuthTimeoutInterval).Unix()
	req, err := http.NewRequest(http.MethodPost, testServer.URL, nil)
	if err != nil {
		t.Errorf("NewRequest error: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+string(tokenBytesLogin))
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("POST error: %v", err)
		return
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status code: %d", resp.StatusCode)
		return
	}

	tokenBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("ReadAll error: %v", err)
	}
	resp.Body.Close()
	// fmt.Printf("tokenBytes :%s\n", string(tokenBytes))
	claimsOut, err := parseClaims(string(tokenBytes))
	expireDiff := expectedExpireTime - claimsOut.ExpiresAt
	// fmt.Printf("expireDiff: %d\n", expireDiff)
	if err != nil || expireDiff < -5 || expireDiff > 5 {
		t.Errorf("token not valid and should be, error: %+v", err)
		return
	}

	// verify login token is invalid
	req, err = http.NewRequest(http.MethodPost, testServer.URL, nil)
	if err != nil {
		t.Errorf("NewRequest error: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+string(tokenBytesLogin))
	resp, err = client.Do(req)
	if err != nil {
		t.Errorf("POST error: %v", err)
		return
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status code: %d", resp.StatusCode)
		return
	}
}

func TestRemoveExpiredTokens(t *testing.T) {
	testSetup(t)

	durations := []time.Duration{time.Duration(0), time.Duration(500) * time.Millisecond}
	removeDuration := time.Duration(100) * time.Millisecond
	for _, v := range durations {
		config.JWTAuthTimeoutInterval = v
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
		b, err := kviToken.Get(claimsOut.tokenKVSKey())
		if b == nil || err != nil {
			t.Errorf("kviToken.Get error: %v", err)
			return
		}

		removeExpiredTokens(removeDuration, removeDuration)
		time.Sleep(removeDuration * 2)
		b, _ = kviToken.Get(claimsOut.tokenKVSKey())
		if b != nil && v < removeDuration {
			t.Errorf("kviToken.Get returned bytes and should not have")
			return
		} else {
			fmt.Printf("TestRemoveExpiredTokens negative test passed\n")
		}
	}
}

func TestValidateNegative(t *testing.T) {
	testSetup(t)

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
	testSetup(t)

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
	c, err := kviAuth.Delete(id)
	return c, runtimeh.SourceInfoError("authDelete error", err)
}

func createAuth(t *testing.T, email *string) (string, []byte, error) {
	// create auth (user)
	em := "someone@auth.com"
	if email != nil {
		em = *email
	}
	ps := "P@ssword1234"
	cred := &Credential{Email: &em, Password: &ps}
	cred.AuthCreate()
	b, err := json.Marshal(cred)
	if err != nil {
		t.Errorf("marshal error: %v", err)
		return "", nil, err
	}
	return em, b, nil
}

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
	tokenBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("ReadAll error: %v", err)
		return nil, nil, err
	}
	resp.Body.Close()
	fmt.Printf("tokenBytes :%s\n", string(tokenBytes))
	claimsOut, err := parseClaims(string(tokenBytes))
	if err != nil {
		t.Errorf("parseClaims error: %v", err)
		return nil, nil, err
	}
	return tokenBytes, claimsOut, err
}

func handlerTest(w http.ResponseWriter, r *http.Request) {
	fmt.Println("handlerTest was called!")
	// Return with something other than default (200), so it is clear the handler was processed
	w.WriteHeader(http.StatusNoContent)
}

func testSetup(t *testing.T) {
	os.Remove(dataSourceName)

	// Can't use Init directly, as config is not Init'd, and many config parameters
	// are app dependent.
	// Init("testingApp", "", "", dataSourceName)
	initializeConfig()
	config.DataSourceName = dataSourceName
	initializeKVS(dataSourceName)
	passwordValidationLoad()
}

func initializeConfig() {
	config = Config{AppName: "auth", AuditLogName: "auth.audit", LogName: "auth", JWTAuthTimeoutInterval: time.Minute * 15}
}
