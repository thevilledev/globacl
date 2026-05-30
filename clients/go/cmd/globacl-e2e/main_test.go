package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/thevilledev/globacl/clients/go/globacl"
)

func TestSeedDeniesUsesDeterministicUserKeys(t *testing.T) {
	var mu sync.Mutex
	var requests []globacl.DenyMutationRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/deny" {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		var request globacl.DenyMutationRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		requests = append(requests, request)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"action":"deny",
			"committed_at_unix":1,
			"delivery_priority":"p1",
			"duplicate":false,
			"entries_changed":1,
			"epoch":1,
			"key_hash":1,
			"seq":1,
			"shard_id":1
		}`))
	}))
	defer server.Close()

	err := seedDenies([]string{
		"--base-url", server.URL,
		"--count", "3",
		"--keyspace", "100",
		"--concurrency", "1",
		"--op-prefix", "test-seed",
		"--progress-every", "0",
	})
	if err != nil {
		t.Fatalf("seedDenies returned error: %v", err)
	}

	wantKeys := []string{"user-0", "user-1", "user-2"}
	if len(requests) != len(wantKeys) {
		t.Fatalf("got %d requests, want %d", len(requests), len(wantKeys))
	}
	for index, wantKey := range wantKeys {
		if requests[index].Key != wantKey {
			t.Fatalf("request %d key = %q, want %q", index, requests[index].Key, wantKey)
		}
		wantOpID := "test-seed-" + wantKey[len("user-"):]
		if requests[index].OpId != wantOpID {
			t.Fatalf("request %d op_id = %q, want %q", index, requests[index].OpId, wantOpID)
		}
	}
}

func TestSeedDeniesRetriesTransientWriteFailure(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/deny" {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		mu.Lock()
		requests++
		currentRequest := requests
		mu.Unlock()
		if currentRequest == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unavailable","reason":"commitd_proxy_failed"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"action":"deny",
			"committed_at_unix":1,
			"delivery_priority":"p1",
			"duplicate":false,
			"entries_changed":1,
			"epoch":1,
			"key_hash":1,
			"seq":1,
			"shard_id":1
		}`))
	}))
	defer server.Close()

	err := seedDenies([]string{
		"--base-url", server.URL,
		"--count", "1",
		"--keyspace", "100",
		"--concurrency", "1",
		"--retries", "1",
		"--retry-delay", "0",
		"--progress-every", "0",
	})
	if err != nil {
		t.Fatalf("seedDenies returned error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestLoadDemoValidatesDemoDecisions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/access" {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		key := r.URL.Query().Get("key")
		if key == "user-0" || key == "user-1" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"access":"denied"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access":"allowed"}`))
	}))
	defer server.Close()

	err := loadDemo([]string{
		"--base-url", server.URL,
		"--duration", "50ms",
		"--workers", "1",
		"--keyspace", "10",
		"--denied-count", "2",
		"--deny-ratio", "1",
		"--progress-every", "0",
	})
	if err != nil {
		t.Fatalf("loadDemo returned error: %v", err)
	}
}

func TestLoadKeyKeepsAllowedKeysOutsideSeededRange(t *testing.T) {
	for sequence := int64(0); sequence < 20; sequence++ {
		key, denied := loadKey(sequence, 10, 3, 0)
		if denied {
			t.Fatalf("loadKey marked sequence %d as denied", sequence)
		}
		switch key {
		case "user-0", "user-1", "user-2":
			t.Fatalf("loadKey returned seeded key %q for allowed lookup", key)
		}
	}
}
