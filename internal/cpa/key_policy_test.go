package cpa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestKeyPolicySnapshotHandling(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		count   int
		wantErr bool
	}{
		{"installed", 200, `{"keys":[{"id":"alice-id","name":"Alice","key_hash":"never-use-as-credential"}]}`, 1, false},
		{"absent", 404, `{}`, 0, false},
		{"unavailable", 500, `{}`, 0, true},
		{"invalid", 200, `{}`, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v0/management/plugins/cpa-key-policy/keys" || r.URL.Query().Get("limit") != "1000" || r.Header.Get("Authorization") != "Bearer test-secret" {
					t.Error("wrong metadata request")
				}
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer server.Close()
			keys, err := NewClient(server.URL, "test-secret", time.Second, false).FetchKeyPolicyKeys(context.Background())
			if (err != nil) != tc.wantErr || len(keys) != tc.count {
				t.Fatalf("count=%d err=%v", len(keys), err)
			}
		})
	}
}
