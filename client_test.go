package jwksclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TODO: Write actual test
func TestNewClient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		return
	}))

	c := New(ts.URL)
	key, err := c.GetKey("abc")

	if err != nil {
		t.Fatal(err)
	}

	_ = key
}
