package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	authIdentitySuccessTTL = 10 * time.Minute
	authIdentityFailureTTL = time.Minute
)

var errAuthRuntimeLookupFailed = errors.New("host runtime auth lookup failed")

// authRuntimeMetadata contains only sanitized presentation metadata returned by
// host.auth.get_runtime. Credential JSON, auth IDs, paths, and auth indexes are
// never persisted; sanitized metadata is cached in memory for a short TTL.
type authRuntimeMetadata struct {
	Provider    string
	Type        string
	Email       string
	AccountType string
	Account     string
	Label       string
}

type authRuntimeLookup func(authKey string) (authRuntimeMetadata, error)

type authIdentityResolver struct {
	lookup authRuntimeLookup
	now    func() time.Time

	mu       sync.Mutex
	entries  map[[sha256.Size]byte]authIdentityCacheEntry
	inFlight map[[sha256.Size]byte]*authIdentityFlight
}

type authIdentityCacheEntry struct {
	metadata authRuntimeMetadata
	err      error
	expires  time.Time
}

type authIdentityFlight struct {
	done chan struct{}
}

type usageIdentity struct {
	Provider string
	Account  string
}

func newAuthIdentityResolver(lookup authRuntimeLookup) *authIdentityResolver {
	return &authIdentityResolver{
		lookup:   lookup,
		now:      time.Now,
		entries:  make(map[[sha256.Size]byte]authIdentityCacheEntry),
		inFlight: make(map[[sha256.Size]byte]*authIdentityFlight),
	}
}

func (r *authIdentityResolver) resolve(authIndex string, usage Dimensions) (usageIdentity, error) {
	if r == nil || r.lookup == nil || strings.TrimSpace(authIndex) == "" {
		return usageIdentity{}, nil
	}
	authIndex = strings.TrimSpace(authIndex)
	cacheKey := sha256.Sum256([]byte(authIndex))
	now := r.now()

	r.mu.Lock()
	if cached, ok := r.entries[cacheKey]; ok && now.Before(cached.expires) {
		r.mu.Unlock()
		if cached.err != nil {
			return usageIdentity{}, cached.err
		}
		return identityFromRuntimeMetadata(cached.metadata, usage), nil
	}
	if flight := r.inFlight[cacheKey]; flight != nil {
		r.mu.Unlock()
		<-flight.done
		return r.resolve(authIndex, usage)
	}
	flight := &authIdentityFlight{done: make(chan struct{})}
	r.inFlight[cacheKey] = flight
	r.mu.Unlock()

	metadata, err := r.lookup(authIndex)
	if err == nil {
		metadata = sanitizeAuthRuntimeMetadata(metadata)
	}
	lookupErr := err
	if err != nil {
		lookupErr = errAuthRuntimeLookupFailed
	}
	ttl := authIdentitySuccessTTL
	if err != nil {
		ttl = authIdentityFailureTTL
	}

	r.mu.Lock()
	r.entries[cacheKey] = authIdentityCacheEntry{metadata: metadata, err: lookupErr, expires: r.now().Add(ttl)}
	delete(r.inFlight, cacheKey)
	close(flight.done)
	r.mu.Unlock()
	if err != nil {
		return usageIdentity{}, lookupErr
	}
	return identityFromRuntimeMetadata(metadata, usage), nil
}

func sanitizeAuthRuntimeMetadata(metadata authRuntimeMetadata) authRuntimeMetadata {
	metadata.Provider = normalizeDimension(metadata.Provider)
	metadata.Type = normalizeDimension(metadata.Type)
	metadata.Email = safeAuthAccount(metadata.Email)
	metadata.AccountType = normalizeDimension(metadata.AccountType)
	if strings.EqualFold(metadata.AccountType, "oauth") {
		metadata.Account = safeAuthAccount(metadata.Account)
	} else {
		metadata.Account = ""
	}
	metadata.Label = safeAuthLabel(metadata.Label)
	return metadata
}

func identityFromRuntimeMetadata(metadata authRuntimeMetadata, usage Dimensions) usageIdentity {
	provider := displayAuthProvider(firstNonEmptyIdentity(metadata.Provider, metadata.Type, usage.Provider, usage.ExecutorType))
	account := safeAuthAccount(metadata.Email)
	if account == "" && strings.EqualFold(strings.TrimSpace(metadata.AccountType), "oauth") {
		account = safeAuthAccount(metadata.Account)
	}
	if account == "" {
		account = safeAuthLabel(metadata.Label)
	}
	return usageIdentity{Provider: provider, Account: account}
}

func displayAuthProvider(value string) string {
	value = normalizeDimension(value)
	switch strings.ToLower(value) {
	case "codex":
		return "Codex"
	case "antigravity":
		return "Antigravity"
	case "xai", "x-ai", "grok":
		return "Grok"
	default:
		return value
	}
}

func safeAuthAccount(value string) string {
	value = normalizeDimension(value)
	if value == "" || strings.ContainsAny(value, "/\\\r\n\t") || looksLikeCredential(value) {
		return ""
	}
	return value
}

func safeAuthLabel(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "/\\\r\n\t") || looksLikeCredential(value) {
		return ""
	}
	return normalizeDimension(value)
}

func firstNonEmptyIdentity(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

type authIdentityDiagnostics struct {
	MissingAuthKey atomic.Uint64
	LookupFailed   atomic.Uint64
	AccountEmpty   atomic.Uint64
	AccountFound   atomic.Uint64
}

func (d *authIdentityDiagnostics) snapshot() map[string]uint64 {
	if d == nil {
		return map[string]uint64{}
	}
	return map[string]uint64{
		"missing_auth_key": d.MissingAuthKey.Load(),
		"lookup_failed":    d.LookupFailed.Load(),
		"account_empty":    d.AccountEmpty.Load(),
		"account_found":    d.AccountFound.Load(),
	}
}

func encodeAccountIdentityDiagnostics(values map[string]uint64) string {
	return fmt.Sprintf("missing=%d;lookup_failed=%d;empty=%d;found=%d",
		values["missing_auth_key"],
		values["lookup_failed"],
		values["account_empty"],
		values["account_found"],
	)
}

func (r *pluginRuntime) setAuthRuntimeLookup(lookup authRuntimeLookup) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if lookup == nil {
		r.authResolver = nil
		return
	}
	r.authResolver = newAuthIdentityResolver(lookup)
}
func (r *pluginRuntime) resolveUsageIdentity(usage *normalizedUsage) {
	if usage == nil {
		return
	}
	defer func() {
		usage.authIndex = ""
		usage.authID = ""
	}()
	authKey := strings.TrimSpace(usage.authIndex)
	if authKey == "" {
		authKey = strings.TrimSpace(usage.authID)
	}
	if authKey == "" {
		r.authDiagnostics.MissingAuthKey.Add(1)
		return
	}
	r.mu.RLock()
	resolver := r.authResolver
	r.mu.RUnlock()
	if resolver == nil {
		r.authDiagnostics.LookupFailed.Add(1)
		return
	}
	identity, err := resolver.resolve(authKey, usage.Dimensions)
	if err != nil {
		r.authDiagnostics.LookupFailed.Add(1)
		return
	}
	usage.Dimensions.Account = identity.Account
	if identity.Account == "" {
		r.authDiagnostics.AccountEmpty.Add(1)
		return
	}
	r.authDiagnostics.AccountFound.Add(1)
}
