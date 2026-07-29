package portal

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminAuth(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := AdminAuth("correct-password", inner)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	t.Run("correct password", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		req.SetBasicAuth("admin", "correct-password")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		req.SetBasicAuth("admin", "wrong-password")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("no credentials", func(t *testing.T) {
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})
}
