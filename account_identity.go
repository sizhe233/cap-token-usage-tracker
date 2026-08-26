package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

const accountReferencePrefix = "acct_"

type accountTrackingContext struct {
	key     []byte
	enabled bool
}

func deriveAccountTrackingContext(secret string) (accountTrackingContext, error) {
	if secret == "" {
		return accountTrackingContext{}, nil
	}
	if len([]byte(secret)) < 32 {
		return accountTrackingContext{}, errors.New("account_tracking_secret must be empty or at least 32 bytes")
	}
	return accountTrackingContext{key: []byte(secret), enabled: true}, nil
}

func accountReference(authIndex string, context accountTrackingContext) string {
	if !context.enabled {
		return ""
	}
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" {
		return ""
	}
	mac := hmac.New(sha256.New, context.key[:])
	_, _ = mac.Write([]byte(authIndex))
	return accountReferencePrefix + hex.EncodeToString(mac.Sum(nil)[:16])
}

func validAccountReference(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != len(accountReferencePrefix)+32 || !strings.HasPrefix(value, accountReferencePrefix) {
		return false
	}
	decoded, err := hex.DecodeString(value[len(accountReferencePrefix):])
	return err == nil && len(decoded) == 16 && strings.ToLower(value) == value
}
