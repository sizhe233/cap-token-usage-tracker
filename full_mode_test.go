package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestFullModeSessionProtectsFullModeResources(t *testing.T) {
	config := testConfig(t)
	store, err := openStore(config)
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := deriveCryptoContext(config.APIKeySecret)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &pluginRuntime{store: store, config: config, crypto: crypto}
	defer runtime.shutdown()
	raw, err := json.Marshal(pluginapi.ManagementRegistrationRequest{ResourceBasePath: "/v0/resource/plugins/test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.registerManagement(raw); err != nil {
		t.Fatal(err)
	}

	dashboardRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.fullDashboardPath})
	response, err := runtime.handleManagement(dashboardRequest)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("full dashboard shell: %+v, %v", response, err)
	}
	if string(response.Body) == "" || containsSensitiveFullModePayload(response.Body) {
		t.Fatal("full dashboard shell must not include protected data")
	}

	dataRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.fullModeDataPath})
	response, err = runtime.handleManagement(dataRequest)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing full-mode session response: %+v, %v", response, err)
	}
	pricesRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.fullModePricesPath})
	response, err = runtime.handleManagement(pricesRequest)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing full-mode session for prices response: %+v, %v", response, err)
	}

	sessionRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodPost, Path: runtime.routes.fullModeSessionPath})
	response, err = runtime.handleManagement(sessionRequest)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("full-mode session response: %+v, %v", response, err)
	}
	var payload struct {
		Session string `json:"session"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil || len(payload.Session) < 40 {
		t.Fatal("full-mode session response must contain an opaque token")
	}

	validRequest, _ := json.Marshal(pluginapi.ManagementRequest{
		Method:  http.MethodGet,
		Path:    runtime.routes.fullModeDataPath,
		Headers: http.Header{"X-Full-Mode-Session": []string{payload.Session}},
	})
	response, err = runtime.handleManagement(validRequest)
	if err != nil || response.StatusCode != http.StatusOK || !containsSensitiveFullModePayload(response.Body) {
		t.Fatalf("valid full-mode session response: %+v, %v", response, err)
	}
	revokeRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.fullModeSessionRevokePath, Headers: http.Header{"X-Full-Mode-Session": []string{payload.Session}}})
	response, err = runtime.handleManagement(revokeRequest)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("full-mode session revoke response: %+v, %v", response, err)
	}
	response, err = runtime.handleManagement(validRequest)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked full-mode session response: %+v, %v", response, err)
	}

	response, err = runtime.handleManagement(sessionRequest)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("replacement full-mode session response: %+v, %v", response, err)
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		t.Fatal(err)
	}
	validRequest, _ = json.Marshal(pluginapi.ManagementRequest{
		Method:  http.MethodGet,
		Path:    runtime.routes.fullModeDataPath,
		Headers: http.Header{"X-Full-Mode-Session": []string{payload.Session}},
	})

	token, err := base64.RawURLEncoding.DecodeString(payload.Session)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(token)
	runtime.fullModeMu.Lock()
	runtime.fullModeSessions[hash] = fullModeSession{expiresAt: time.Now().UTC().Add(-time.Second)}
	runtime.fullModeMu.Unlock()
	response, err = runtime.handleManagement(validRequest)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired full-mode session response: %+v, %v", response, err)
	}
}

func TestFullModeSessionCreationIsBounded(t *testing.T) {
	runtime := &pluginRuntime{}
	defer runtime.shutdown()
	for range maxFullModeSessions {
		if _, err := runtime.createFullModeSession(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := runtime.createFullModeSession(); err == nil {
		t.Fatal("session limit did not reject another active capability")
	}
}

func TestResourceDataRoutesRequireAuthenticatedSession(t *testing.T) {
	config := testConfig(t)
	store, err := openStore(config)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &pluginRuntime{store: store, config: config}
	defer runtime.shutdown()
	registration, err := json.Marshal(pluginapi.ManagementRegistrationRequest{ResourceBasePath: "/v0/resource/plugins/test"})
	if err != nil {
		t.Fatal(err)
	}
	now := nowUTC()
	rate := ExchangeRateResponse{SchemaVersion: 1, Base: "USD", Quote: "CNY", Rate: 7.2, EffectiveAt: now, FetchedAt: now, Source: "test"}
	runtime.exchangeRates = &exchangeRateService{cached: &rate, freshUntil: now.Add(time.Hour), staleUntil: now.Add(time.Hour), now: func() time.Time { return now }}
	if _, err := runtime.registerManagement(registration); err != nil {
		t.Fatal(err)
	}

	call := func(method, path, session string) pluginapi.ManagementResponse {
		t.Helper()
		headers := http.Header{}
		if session != "" {
			headers.Set("X-Full-Mode-Session", session)
		}
		request, err := json.Marshal(pluginapi.ManagementRequest{Method: method, Path: path, Headers: headers})
		if err != nil {
			t.Fatal(err)
		}
		response, err := runtime.handleManagement(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	for _, path := range []string{runtime.routes.dashboardPath, runtime.routes.fullDashboardPath} {
		response := call(http.MethodGet, path, "")
		if response.StatusCode != http.StatusOK || len(response.Body) == 0 {
			t.Fatalf("public shell %s response = %+v", path, response)
		}
	}

	paths := []string{
		runtime.routes.resourceStatsPath,
		runtime.routes.resourceStatsInitialPath,
		runtime.routes.resourceStatsTrendPath,
		runtime.routes.resourceStatsGroupsPath,
		runtime.routes.resourceRequestsPath,
		runtime.routes.resourceCostsPath,
		runtime.routes.resourceExchangeRatePath,
		runtime.routes.resourcePricesPath,
		runtime.routes.resourcePreferencesPath,
	}
	for _, path := range paths {
		if response := call(http.MethodGet, path, ""); response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthenticated resource %s status = %d body=%s", path, response.StatusCode, response.Body)
		}
	}

	session, err := runtime.createFullModeSession()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if response := call(http.MethodGet, path, session); response.StatusCode != http.StatusOK {
			t.Fatalf("valid session response from %s = %d body=%s", path, response.StatusCode, response.Body)
		}
	}

	runtime.revokeFullModeSession(session)
	for _, path := range paths {
		if response := call(http.MethodGet, path, session); response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("revoked session accepted by %s", path)
		}
	}

	expiredSession, err := runtime.createFullModeSession()
	if err != nil {
		t.Fatal(err)
	}
	token, err := base64.RawURLEncoding.DecodeString(expiredSession)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(token)
	runtime.fullModeMu.Lock()
	runtime.fullModeSessions[hash] = fullModeSession{expiresAt: nowUTC().Add(-time.Second)}
	runtime.fullModeMu.Unlock()
	for _, path := range paths {
		if response := call(http.MethodGet, path, expiredSession); response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expired session accepted by %s", path)
		}
	}

	for _, route := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, runtime.routes.statsPath},
		{http.MethodGet, runtime.routes.backupPath},
	} {
		if response := call(route.method, route.path, ""); response.StatusCode == http.StatusUnauthorized {
			t.Fatalf("management route %s incorrectly requires a plugin session", route.path)
		}
	}
}

func TestFullModeAPIKeyTrackingTracksSuccessfulReconfigure(t *testing.T) {
	config := testConfig(t)
	runtime := &pluginRuntime{}
	defer runtime.shutdown()
	lifecyclePayload := func(secret string) []byte {
		configYAML := []byte("data_path: " + filepath.ToSlash(config.DataPath) + "\napi_key_secret: " + strconv.Quote(secret) + "\n")
		payload, err := json.Marshal(lifecycleRequest{ConfigYAML: configYAML, SchemaVersion: 3})
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	if _, err := runtime.register(lifecyclePayload("")); err != nil {
		t.Fatal(err)
	}
	registration, _ := json.Marshal(pluginapi.ManagementRegistrationRequest{ResourceBasePath: "/v0/resource/plugins/test"})
	if _, err := runtime.registerManagement(registration); err != nil {
		t.Fatal(err)
	}
	session, err := runtime.createFullModeSession()
	if err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(pluginapi.ManagementRequest{
		Method:  http.MethodGet,
		Path:    runtime.routes.fullModeDataPath,
		Headers: http.Header{"X-Full-Mode-Session": []string{session}},
	})

	response, err := runtime.handleManagement(request)
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(response.Body), `"api_key_tracking_enabled":false`) {
		t.Fatalf("disabled-tracking full-mode data = %+v, %v", response, err)
	}

	customSecret := strings.Repeat("custom-secret-", 3)
	if _, err := runtime.reconfigure(lifecyclePayload(customSecret)); err != nil {
		t.Fatal(err)
	}
	response, err = runtime.handleManagement(request)
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(response.Body), `"api_key_tracking_enabled":true`) || !strings.Contains(string(response.Body), `"api_key_uses_default_secret":false`) {
		t.Fatalf("custom-secret full-mode data = %+v, %v", response, err)
	}
}

func TestFullModeStagedPriceSaveUsesGETResourceRequests(t *testing.T) {
	config := testConfig(t)
	store, err := openStore(config)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &pluginRuntime{store: store, config: config}
	defer runtime.shutdown()

	raw, _ := json.Marshal(pluginapi.ManagementRegistrationRequest{ResourceBasePath: "/v0/resource/plugins/test"})
	if _, err := runtime.registerManagement(raw); err != nil {
		t.Fatal(err)
	}
	sessionRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodPost, Path: runtime.routes.fullModeSessionPath})
	response, err := runtime.handleManagement(sessionRequest)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("full-mode session response: %+v, %v", response, err)
	}
	var session struct {
		Session string `json:"session"`
	}
	if err := json.Unmarshal(response.Body, &session); err != nil {
		t.Fatal(err)
	}
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"prices":{"full-mode-test":{"input":1.5,"output":6}}}`))
	baseHeaders := http.Header{"X-Full-Mode-Session": []string{session.Session}}

	beginRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.fullModePricesSavePath, Headers: baseHeaders, Query: map[string][]string{"stage": {"begin"}, "chunks": {"1"}}})
	response, err = runtime.handleManagement(beginRequest)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("full-mode upload begin response: %+v, %v", response, err)
	}
	var upload struct {
		Upload string `json:"upload"`
	}
	if err := json.Unmarshal(response.Body, &upload); err != nil || upload.Upload == "" {
		t.Fatalf("full-mode upload begin payload: %s, %v", response.Body, err)
	}

	chunkHeaders := baseHeaders.Clone()
	chunkHeaders.Set("X-Full-Mode-Payload", payload)
	chunkRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.fullModePricesSavePath, Headers: chunkHeaders, Query: map[string][]string{"stage": {"chunk"}, "upload": {upload.Upload}, "index": {"0"}}})
	response, err = runtime.handleManagement(chunkRequest)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("full-mode upload chunk response: %+v, %v", response, err)
	}
	commitRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.fullModePricesSavePath, Headers: baseHeaders, Query: map[string][]string{"stage": {"commit"}, "upload": {upload.Upload}}})
	response, err = runtime.handleManagement(commitRequest)
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(response.Body), `"full-mode-test"`) {
		t.Fatalf("full-mode upload commit response: %+v, %v", response, err)
	}
}

func TestFullModeBackupAndRestoreRequireSession(t *testing.T) {
	config := testConfig(t)
	store, err := openStore(config)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &pluginRuntime{store: store, config: config}
	defer runtime.shutdown()

	raw, _ := json.Marshal(pluginapi.ManagementRegistrationRequest{ResourceBasePath: "/v0/resource/plugins/test"})
	if _, err := runtime.registerManagement(raw); err != nil {
		t.Fatal(err)
	}
	backupRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.fullModeBackupPath})
	response, err := runtime.handleManagement(backupRequest)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized full-mode backup response: %+v, %v", response, err)
	}
	restoreRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.fullModeRestorePath, Query: map[string][]string{"stage": {"begin"}, "chunks": {"1"}}})
	response, err = runtime.handleManagement(restoreRequest)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized full-mode restore response: %+v, %v", response, err)
	}

	sessionRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodPost, Path: runtime.routes.fullModeSessionPath})
	response, err = runtime.handleManagement(sessionRequest)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("full-mode session response: %+v, %v", response, err)
	}
	var session struct {
		Session string `json:"session"`
	}
	if err := json.Unmarshal(response.Body, &session); err != nil || session.Session == "" {
		t.Fatalf("full-mode session payload: %s, %v", response.Body, err)
	}

	headers := http.Header{"X-Full-Mode-Session": []string{session.Session}}
	backupRequest, _ = json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.fullModeBackupPath, Headers: headers})
	response, err = runtime.handleManagement(backupRequest)
	if err != nil || response.StatusCode != http.StatusOK || response.Headers.Get("Content-Type") != "application/octet-stream" || len(response.Body) == 0 {
		t.Fatalf("authorized full-mode backup response: %+v, %v", response, err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(response.Body)
	chunkCount := (len(encoded) + fullModeUploadChunkSize - 1) / fullModeUploadChunkSize
	restoreRequest, _ = json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.fullModeRestorePath, Headers: headers, Query: map[string][]string{"stage": {"begin"}, "chunks": {strconv.Itoa(chunkCount)}}})
	response, err = runtime.handleManagement(restoreRequest)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("full-mode restore begin response: %+v, %v", response, err)
	}
	var upload struct {
		Upload string `json:"upload"`
	}
	if err := json.Unmarshal(response.Body, &upload); err != nil || upload.Upload == "" {
		t.Fatalf("full-mode restore begin payload: %s, %v", response.Body, err)
	}
	for index := 0; index < chunkCount; index++ {
		chunkHeaders := headers.Clone()
		start := index * fullModeUploadChunkSize
		end := start + fullModeUploadChunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		chunkHeaders.Set("X-Full-Mode-Payload", encoded[start:end])
		chunkRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.fullModeRestorePath, Headers: chunkHeaders, Query: map[string][]string{"stage": {"chunk"}, "upload": {upload.Upload}, "index": {strconv.Itoa(index)}}})
		response, err = runtime.handleManagement(chunkRequest)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("full-mode restore chunk %d response: %+v, %v", index, response, err)
		}
	}
	commitHeaders := headers.Clone()
	commitHeaders.Set("X-Confirm-Restore", "replace")
	commitRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.fullModeRestorePath, Headers: commitHeaders, Query: map[string][]string{"stage": {"commit"}, "upload": {upload.Upload}}})
	response, err = runtime.handleManagement(commitRequest)
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(response.Body), `"restored":true`) {
		t.Fatalf("full-mode restore commit response: %+v, %v", response, err)
	}
}

func TestFullModeResetUsesGETResourceContract(t *testing.T) {
	config := testConfig(t)
	store, err := openStore(config)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &pluginRuntime{store: store, config: config}
	defer runtime.shutdown()

	raw, _ := json.Marshal(pluginapi.ManagementRegistrationRequest{ResourceBasePath: "/v0/resource/plugins/test"})
	if _, err := runtime.registerManagement(raw); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(normalizedUsage{Dimensions: Dimensions{Model: "reset-model"}, RequestedAt: nowUTC(), Counters: Counters{Requests: 1, TotalTokens: 5}}); err != nil {
		t.Fatal(err)
	}

	unauthorized, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.fullModeResetPath, Headers: http.Header{"X-Confirm-Reset": []string{"reset"}}})
	response, err := runtime.handleManagement(unauthorized)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing session reset response: %+v, %v", response, err)
	}

	session, err := runtime.createFullModeSession()
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"X-Full-Mode-Session": []string{session}}
	missingConfirmation, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.fullModeResetPath, Headers: headers.Clone()})
	response, err = runtime.handleManagement(missingConfirmation)
	if err != nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing confirmation reset response: %+v, %v", response, err)
	}

	postRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodPost, Path: runtime.routes.fullModeResetPath, Headers: headers.Clone()})
	response, err = runtime.handleManagement(postRequest)
	if err != nil || response.StatusCode != http.StatusMethodNotAllowed || response.Headers.Get("Allow") != http.MethodGet {
		t.Fatalf("resource reset must be GET-only: %+v, %v", response, err)
	}

	headers.Set("X-Confirm-Reset", "reset")
	authorized, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.fullModeResetPath, Headers: headers})
	response, err = runtime.handleManagement(authorized)
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(response.Body), `"reset":true`) {
		t.Fatalf("authorized reset response: %+v, %v", response, err)
	}

	statsRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: runtime.routes.resourceStatsPath, Headers: http.Header{"X-Full-Mode-Session": []string{session}}, Query: map[string][]string{"range": {"24h"}}})
	response, err = runtime.handleManagement(statsRequest)
	if err != nil || response.StatusCode != http.StatusOK || strings.Contains(string(response.Body), "reset-model") {
		t.Fatalf("stats after reset: %+v, %v", response, err)
	}

	body := []byte(`{"confirm":"reset"}`)
	managementHeaders := http.Header{"Content-Type": []string{"application/json"}}
	managementReset, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodPost, Path: runtime.routes.resetPath, Headers: managementHeaders, Body: body})
	response, err = runtime.handleManagement(managementReset)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("management reset route must remain available: %+v, %v", response, err)
	}
}

func TestFullModeUploadBeginEnforcesPayloadAndSessionLimits(t *testing.T) {
	runtime := &pluginRuntime{}
	defer runtime.shutdown()
	session, err := runtime.createFullModeSession()
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"X-Full-Mode-Session": []string{session}}
	call := func(chunks int) pluginapi.ManagementResponse {
		t.Helper()
		request := pluginapi.ManagementRequest{Method: http.MethodGet, Headers: headers, Query: map[string][]string{"stage": {"begin"}, "chunks": {strconv.Itoa(chunks)}}}
		response, callErr := runtime.fullModeStagedPayloadResponse(request, 2<<20, "application/json", func(pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
			return jsonResponse(http.StatusOK, map[string]bool{"ok": true}), nil
		})
		if callErr != nil {
			t.Fatal(callErr)
		}
		return response
	}
	maxChunks := (base64.RawURLEncoding.EncodedLen(2<<20) + fullModeUploadChunkSize - 1) / fullModeUploadChunkSize
	if response := call(maxChunks + 1); response.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized begin status = %d body=%s", response.StatusCode, response.Body)
	}
	for range maxFullModeUploadsPerSession {
		if response := call(1); response.StatusCode != http.StatusOK {
			t.Fatalf("allowed begin status = %d body=%s", response.StatusCode, response.Body)
		}
	}
	if response := call(1); response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("concurrent upload limit status = %d body=%s", response.StatusCode, response.Body)
	}
}

func containsSensitiveFullModePayload(body []byte) bool {
	var payload struct {
		FullMode bool `json:"full_mode"`
	}
	return json.Unmarshal(body, &payload) == nil && payload.FullMode
}
