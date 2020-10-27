// Copyright © 2018 Banzai Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"
	"encoding/base32"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type contextKey string

const userKey = contextKey("user")

func claimConverter(c *ScopedClaims) interface{} {
	return c
}

func contextSetter(c context.Context, value interface{}) context.Context {
	return context.WithValue(c, userKey, value)
}

func contextGetter(c context.Context) interface{} {
	return c.Value(userKey)
}

func TestJWTAuthWithoutTokenStore(t *testing.T) {
	handler := JWTAuthHandler("blabla", claimConverter, contextSetter, contextGetter)
	router := gin.New()
	router.GET("/", handler)

	server := httptest.NewServer(router)
	defer server.Close()

	resp, err := http.Get(server.URL)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "bad status code")
	assert.NoError(t, resp.Body.Close())

	req, err := http.NewRequest("GET", server.URL, nil)
	assert.NoError(t, err)

	jwtHeader, err := signToken(jwt.Claims{})
	assert.NoError(t, err)

	req.Header.Add("Authorization", "Bearer "+jwtHeader)

	resp, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode, "bad status code")
	assert.NoError(t, resp.Body.Close())
}

type inMemoryTokenStore map[string]map[string]bool

func (ts inMemoryTokenStore) Exists(userID, tokenID string) (bool, error) {
	userTokens, ok := ts[userID]
	if !ok {
		return false, nil
	}
	_, ok = userTokens[tokenID]
	return ok, nil
}

func TestJWTAuthWithTokenStore(t *testing.T) {

	tokenStore := inMemoryTokenStore{"1": map[string]bool{"existingTokenID": true}}

	handler := JWTAuthHandler("blabla", claimConverter, contextSetter, contextGetter, TokenStoreOption(tokenStore))

	var currentUser interface{}
	dummyHandler := func(c *gin.Context) {
		currentUser = c.Request.Context().Value(userKey)
	}

	router := gin.New()
	router.GET("/", handler, dummyHandler)

	server := httptest.NewServer(router)
	defer server.Close()

	jwtHeader, err := signToken(jwt.Claims{Subject: "1", ID: "nonExistingTokenID"})
	assert.NoError(t, err)

	req, err := http.NewRequest("GET", server.URL, nil)
	assert.NoError(t, err)

	req.Header.Add("Authorization", "Bearer "+jwtHeader)

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "bad status code")
	assert.NoError(t, resp.Body.Close())

	assert.Nil(t, currentUser, "expected no user in context")

	req, err = http.NewRequest("GET", server.URL, nil)
	assert.NoError(t, err)

	jwtHeader, err = signToken(jwt.Claims{Subject: "1", ID: "existingTokenID"})
	assert.NoError(t, err)

	req.Header.Add("Authorization", "Bearer "+jwtHeader)

	resp, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode, "bad status code")
	assert.NoError(t, resp.Body.Close())

	assert.NotNil(t, currentUser, "expected user in context")
}

func signToken(claims jwt.Claims) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       []byte(base32.StdEncoding.EncodeToString([]byte("blabla"))),
	}, nil)
	if err != nil {
		return "", err
	}

	return jwt.Signed(signer).Claims(claims).CompactSerialize()
}
