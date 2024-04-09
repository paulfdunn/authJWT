package authjwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHandlerFuncAuthJWTWrapper tests the wrapper function to show that wrapping a handler
// does then require authentication.
func TestHandlerFuncAuthJWTWrapper(t *testing.T) {
	testSetup()

	// Test using handlerTest without wrapping in HandlerFuncAuthJWTWrapper.
	// This server does not require auth.
	testServerNoWrap := httptest.NewServer(http.HandlerFunc(handlerTest))
	resp, _ := http.Get(testServerNoWrap.URL)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("HandlerFuncAuthJWTWrapper method did not return proper status: %d", resp.StatusCode)
		return
	}
	testServerNoWrap.Close()

	// Test using handlerTest WITH wrapping in HandlerFuncAuthJWTWrapper.
	// This server DOES require auth.
	testServerWrapped := httptest.NewServer(http.HandlerFunc(HandlerFuncAuthJWTWrapper(handlerTest)))
	resp, _ = http.Get(testServerWrapped.URL)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("HandlerFuncAuthJWTWrapper method did not return proper status: %d", resp.StatusCode)
		return
	}

	// Create auth, get a JWT token, and send a DELETE request; http.StatusNoContent
	// means the request succeeded
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

// TestHandlerCreateOrUpdate tests handlerCreateOrUpdate by creating an auth, verifying a GET
// is rejected, and verifying a POST to an existing credential is rejected.
func TestHandlerCreateOrUpdate(t *testing.T) {
	testSetup()

	testServer := httptest.NewServer(http.HandlerFunc(handlerCreateOrUpdate))

	em := "password-to-long@auth.com"
	pwd := "0123456789012345678901234567890123456789012345678901234567890123456789123"
	cred := Credential{Email: &em, Password: &pwd}
	credBytes, err := json.Marshal(cred)
	if err != nil {
		t.Errorf("TestHandlerCreateOrUpdate marshal error: %v", err)
		return
	}

	resp, err := http.Post(testServer.URL, "application/json", bytes.NewBuffer(credBytes))
	if err != nil {
		t.Errorf("TestHandlerCreateOrUpdate error: %v", err)
		return
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("TestHandlerCreateOrUpdate did not return proper status: %d", resp.StatusCode)
		return
	}

	em = "newAuth@auth.com"
	pwd = "P@ass!234"
	cred = Credential{Email: &em, Password: &pwd}
	credBytes, err = json.Marshal(cred)
	if err != nil {
		t.Errorf("TestHandlerCreateOrUpdate marshal error: %v", err)
		return
	}

	// negative test - GET not allowed.
	resp, _ = http.Get(testServer.URL)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("invalid method did not return proper status: %d", resp.StatusCode)
		return
	}

	resp, err = http.Post(testServer.URL, "application/json", bytes.NewBuffer(credBytes))
	if err != nil {
		t.Errorf("TestHandlerCreateOrUpdate error: %v", err)
		return
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("TestHandlerCreateOrUpdate did not return proper status: %d", resp.StatusCode)
		return
	}

	_, err = kvsAuth.Get(em)
	if err != nil {
		t.Errorf("Get kvsAuth error: %v", err)
		return
	}
	// No error, auth was created.

	// negative test - should error on creating existing auth
	resp, err = http.Post(testServer.URL, "application/json", bytes.NewBuffer(credBytes))
	if err != nil {
		t.Errorf("TestHandlerCreateOrUpdate error: %v", err)
		return
	}
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("TestHandlerCreateOrUpdate did not return proper status: %d", resp.StatusCode)
		return
	}

	// positive test - credential update.
	// Login with current creds.
	tokenBytes, _, err := login(t, credBytes)
	if err != nil {
		return
	}
	// Change creds.
	pwd = "P@ass432!"
	cred = Credential{Email: &em, Password: &pwd}
	credBytes, err = json.Marshal(cred)
	if err != nil {
		t.Errorf("TestHandlerCreateOrUpdate marshal error: %v", err)
		return
	}
	// Update creds with token from login.
	req, err := http.NewRequest(http.MethodPut, testServer.URL, bytes.NewBuffer(credBytes))
	if err != nil {
		t.Errorf("NewRequest error: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+string(tokenBytes))
	client := http.Client{}
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Errorf("TestHandlerCreateOrUpdate did not return proper status: %d", resp.StatusCode)
		return
	}
	// Login with updated creds.
	_, _, err = login(t, credBytes)
	if err != nil {
		t.Errorf("TestHandlerCreateOrUpdate could not login with updated creds, error: %d", err)
		return
	}
}

// TestHandlerDelete creates an auth via direct function calls and verifies a call to the
// delete handler deletes the auth.
func TestHandlerDelete(t *testing.T) {
	testSetup()

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
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("TestHandlerDelete did not return proper status: %d", resp.StatusCode)
		return
	}

	_, credBytes, err := createAuth(t, nil)
	if err != nil {
		return
	}
	tokenBytes, _, err := login(t, credBytes)
	if err != nil {
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

	// kvsBytes, err := kvsAuth.Get(em)
	// if err != nil || kvsBytes != nil {
	// 	t.Error("Get kvsAuth had no error, or returned bytes, and should not have")
	// 	return
	// }
}

// TestHandlerInfo does several logins for one user and verifies the Info returned.
func TestHandlerInfo(t *testing.T) {
	testSetup()

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
	_, credBytes, err = createAuth(t, &userManyLogins)
	if err != nil {
		return
	}
	var tokenBytes []byte
	for i := 0; i < manyLogins; i++ {

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
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("reading body error: %v", err)
		return
	}
	info := Info{}
	err = json.Unmarshal(respBytes, &info)
	if err != nil {
		t.Errorf("unmarshal error: %v", err)
		return
	}
	// fmt.Printf("%+v\n", info)
	if info.OutstandingTokens != manyLogins {
		t.Errorf("Wrong number of OutstandingTokens")
	}
}

// TestHandlerLogin runs two tests, one positive test and one negative test, of the login handler.
func TestHandlerLogin(t *testing.T) {
	testSetup()

	// Loop 0 - positive test:
	// create credentials, PUT with no body to verify error, PUT with credentials to
	// verify the returned body can be parsed to a token.
	// loop 1 - negative test; login with no auth created.
	// create then delete credentials, PUT with no body to verify error, PUT with credentials to
	// verify the returned body can be parsed to a token.
	for i := 0; i <= 1; i++ {

		// For i==1 get credentials but delete the auth.
		tem := fmt.Sprintf("testLogin@auth.com.%d", i)
		_, credBytes, err := createAuth(t, &tem)
		if err != nil {
			t.Errorf("createAuth error:%+v", err)
			return
		}
		if i == 1 {
			if _, err := authDelete(tem); err != nil {
				t.Errorf("authDelete error: %+v", err)
				return
			}
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

		// negative test - PUT with no body.
		client := &http.Client{}
		req, err := http.NewRequest(http.MethodPut, testServer.URL, nil)
		if err != nil {
			t.Errorf("NewRequest error: %v", err)
			return
		}
		resp, err = client.Do(req)
		if err != nil || resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("error or Put with no body did not return proper status: %d", resp.StatusCode)
			return
		}

		// positive test - PUT with credentials
		expectedExpireTime := time.Now().Add(config.JWTAuthExpirationInterval).Unix()
		req, err = http.NewRequest(http.MethodPut, testServer.URL, bytes.NewBuffer(credBytes))
		if err != nil {
			t.Errorf("NewRequest error: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err = client.Do(req)
		if err != nil {
			t.Errorf("PUT error: %v", err)
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

		tokenBytes, err := io.ReadAll(resp.Body)
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
	testSetup()

	_, credBytes, err := createAuth(t, nil)
	if err != nil {
		return
	}

	tokenBytes, claims, err := login(t, credBytes)
	if err != nil {
		return
	}

	// logout and verify token deleted from kvsToken
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
	} else if resp == nil || resp.StatusCode != http.StatusNoContent {
		t.Errorf("Logout did not return proper status or was nil: %d", resp.StatusCode)
		return
	}
	kvsBytes, err := kvsToken.Get(claims.tokenKVSKey())
	if !(kvsBytes == nil && err == nil) {
		t.Error("TokenID not deleted.")
		return
	}
}

func TestHandlerLogoutAll(t *testing.T) {
	testSetup()

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

	k, err := kvsToken.Keys()
	if len(k) != 1 || err != nil {
		t.Errorf("There should still be one user token.")
	}
}

func TestHandlerRefresh(t *testing.T) {
	testSetup()

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

	expectedExpireTime := time.Now().Add(config.JWTAuthExpirationInterval).Unix()
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

	tokenBytes, err := io.ReadAll(resp.Body)
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

func handlerTest(w http.ResponseWriter, r *http.Request) {
	// fmt.Println("handlerTest was called!")
	// Return with something other than default (200), so it is clear the handler was processed
	w.WriteHeader(http.StatusNoContent)
}
