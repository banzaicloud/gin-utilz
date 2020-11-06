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
	"fmt"
	"net/http"
	"time"

	"emperror.dev/errors"
	"github.com/gin-gonic/gin"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Errors
var (
	ErrNoTokenInRequest = errors.New("no token present in request")
)

// TokenExtractor is an interface for extracting a token from an HTTP request.
// The ExtractToken method should return a token string or an error.
// If no token is present, you must return ErrNoTokenInRequest.
type TokenExtractor interface {
	ExtractToken(*http.Request) (string, error)
}

type MultiTokenExtractor []TokenExtractor

func (e MultiTokenExtractor) ExtractToken(req *http.Request) (string, error) {
	for _, extractor := range e {
		if tok, err := extractor.ExtractToken(req); tok != "" {
			return tok, nil
		} else if err != ErrNoTokenInRequest {
			return "", err
		}
	}
	return "", ErrNoTokenInRequest
}

type Oauth2TokenExtractor struct{}

func (Oauth2TokenExtractor) ExtractToken(r *http.Request) (string, error) {
	token := r.Header.Get("Authorization")

	// first we attempt to get the token from the
	// authorization header.
	if len(token) != 0 {
		token = r.Header.Get("Authorization")
		_, err := fmt.Sscanf(token, "Bearer %s", &token)
		return token, err
	}

	// then we attempt to get the token from the
	// access_token url query parameter
	token = r.FormValue("access_token")
	if len(token) != 0 {
		return token, nil
	}

	return "", ErrNoTokenInRequest
}

type TokenStore interface {
	Exists(userID, tokenID string) (bool, error)
}

// TokenType represents one of the possible token Types
type TokenType string

// ClaimConverter converts claims to another domain object for saving into Context
type ClaimConverter func(*ScopedClaims) interface{}

// ScopedClaims struct to store the scoped claim related things
type ScopedClaims struct {
	jwt.Claims
	Scope string `json:"scope,omitempty"`
	// Drone fields
	Type TokenType `json:"type,omitempty"`
	Text string    `json:"text,omitempty"`
}

type options struct {
	tokenStore   TokenStore
	extractors   []TokenExtractor
	errorHandler ErrorHandler
}

type Option interface {
	apply(o *options)
}

// ContextSetter adds the resolved (and converted) claims to a context.
type ContextSetter func(c context.Context, value interface{}) context.Context

// ContextGetter gets the resolved (and converted) claims from a context.
type ContextGetter func(c context.Context) interface{}

type optionFunc func(o *options)

func (fn optionFunc) apply(o *options) {
	fn(o)
}

func TokenStoreOption(tokenStore TokenStore) Option {
	return optionFunc(func(o *options) {
		o.tokenStore = tokenStore
	})
}

func TokenExtractorOption(extractor TokenExtractor) Option {
	return optionFunc(func(o *options) {
		o.extractors = append(o.extractors, extractor)
	})
}

func ErrorHandlerOption(errorHandler ErrorHandler) Option {
	return optionFunc(func(o *options) {
		o.errorHandler = errorHandler
	})
}

// JWTAuthHandler returns a new JWT authentication Gin Handler
// Parameters:
// - signingKey - the HMAC JWT token signing key
// - claimConverter - converts the JWT token into a JWT claim object, which will be saved into the request context
// - extractors (optional) - additional token extractors to use besides OAuth2Extractor
// - tokenStore (optional) - checks if the incoming JWT Bearer token's ID is present in this TokenStore
//							(can be nil, which pypasses the check)
func JWTAuthHandler(
	signingKey string,
	claimConverter ClaimConverter,
	contextSetter ContextSetter,
	contextGetter ContextGetter,
	opts ...Option,
) gin.HandlerFunc {
	o := &options{
		errorHandler: noopErrorHandler{},
	}

	for _, opt := range opts {
		opt.apply(o)
	}

	signingKeyBase32 := []byte(base32.StdEncoding.EncodeToString([]byte(signingKey)))

	extractor := append(MultiTokenExtractor{Oauth2TokenExtractor{}}, o.extractors...)

	return func(c *gin.Context) {

		// If antoher handler (another auth method) has set a user already, we can bail out.
		if contextGetter(c.Request.Context()) != nil {
			return
		}

		rawToken, err := extractor.ExtractToken(c.Request)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{
					"message": "Failed to extract token from request",
					"error":   err.Error(),
				})

			return
		}

		token, err := jwt.ParseSigned(rawToken)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{
					"message": "Failed to parse token",
					"error":   err.Error(),
				})

			return
		}

		var claims ScopedClaims
		err = token.Claims(signingKeyBase32, &claims)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{
					"message": "Invalid token",
					"error":   err.Error(),
				})

			return
		}

		err = claims.Validate(jwt.Expected{Time: time.Now()})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{
					"message": "Invalid token",
					"error":   err.Error(),
				})

			return
		}

		tokenPresentInStore, err := isTokenValidInTokenStore(o.tokenStore, &claims)
		if err != nil {
			o.errorHandler.Handle(c.Request.Context(), errors.WrapIf(err, "failed to lookup user token"))

			c.AbortWithStatusJSON(
				http.StatusInternalServerError,
				gin.H{
					"message": "Failed to validate user token",
					"error":   err.Error(),
				},
			)

			return
		}

		if !tokenPresentInStore {
			c.AbortWithStatusJSON(
				http.StatusUnauthorized,
				gin.H{
					"message": "Invalid token",
					"error":   "no matching token in token store",
				},
			)

			return
		}

		var toSave interface{} = claims
		if claimConverter != nil {
			toSave = claimConverter(&claims)
		}

		c.Request = c.Request.WithContext(contextSetter(c.Request.Context(), toSave))
	}
}

func isTokenValidInTokenStore(tokenStore TokenStore, claims *ScopedClaims) (bool, error) {
	if tokenStore == nil {
		return true, nil
	}

	userID := claims.Subject
	tokenID := claims.ID

	return tokenStore.Exists(userID, tokenID)
}
