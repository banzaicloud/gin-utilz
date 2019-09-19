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

	"emperror.dev/errors"
	"github.com/dgrijalva/jwt-go"
	jwtRequest "github.com/dgrijalva/jwt-go/request"
	"github.com/gin-gonic/gin"
)

type TokenStore interface {
	Exists(userID, tokenID string) (bool, error)
}

// TokenType represents one of the possible token Types
type TokenType string

// ClaimConverter converts claims to another domain object for saving into Context
type ClaimConverter func(*ScopedClaims) interface{}

// ScopedClaims struct to store the scoped claim related things
type ScopedClaims struct {
	jwt.StandardClaims
	Scope string `json:"scope,omitempty"`
	// Drone fields
	Type TokenType `json:"type,omitempty"`
	Text string    `json:"text,omitempty"`
}

type options struct {
	tokenStore   TokenStore
	extractors   []jwtRequest.Extractor
	errorHandler ErrorHandler
}

type Option interface {
	apply(o *options)
}

// ContextSetter adds the resolved (and converted) claims to a context.
type ContextSetter func(c context.Context, value interface{}) context.Context

type optionFunc func(o *options)

func (fn optionFunc) apply(o *options) {
	fn(o)
}

func TokenStoreOption(tokenStore TokenStore) Option {
	return optionFunc(func(o *options) {
		o.tokenStore = tokenStore
	})
}

func ExtractorOption(extractor jwtRequest.Extractor) Option {
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
// - extractors (optional) - additional token extractors to use besides
// 							github.com/dgrijalva/jwt-go/request.OAuth2Extractor
// - tokenStore (optional) - checks if the incoming JWT Bearer token's ID is present in this TokenStore
//							(can be nil, which pypasses the check)
func JWTAuthHandler(
	signingKey string,
	claimConverter ClaimConverter,
	contextSetter ContextSetter,
	opts ...Option,
) gin.HandlerFunc {
	o := &options{
		errorHandler: noopErrorHandler{},
	}

	for _, opt := range opts {
		opt.apply(o)
	}

	signingKeyBase32 := []byte(base32.StdEncoding.EncodeToString([]byte(signingKey)))

	hmacKeyFunc := func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Method.Alg())
		}
		return signingKeyBase32, nil
	}

	extractor := append(jwtRequest.MultiExtractor{jwtRequest.OAuth2Extractor}, o.extractors...)

	return func(c *gin.Context) {
		var claims ScopedClaims
		accessToken, err := jwtRequest.ParseFromRequest(c.Request, extractor, hmacKeyFunc, jwtRequest.WithClaims(&claims))

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{
					"message": "Invalid token",
					"error":   err.Error(),
				})

			return
		}

		isTokenWhitelisted, err := isTokenWhitelisted(o.tokenStore, &claims)

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

		if !accessToken.Valid || !isTokenWhitelisted {
			c.AbortWithStatusJSON(
				http.StatusUnauthorized,
				gin.H{
					"message": "Invalid token",
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

func isTokenWhitelisted(tokenStore TokenStore, claims *ScopedClaims) (bool, error) {
	if tokenStore == nil {
		return true, nil
	}

	userID := claims.Subject
	tokenID := claims.Id

	return tokenStore.Exists(userID, tokenID)
}
