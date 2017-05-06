package jwksclient

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	jose "github.com/square/go-jose"
)

var httpClient *http.Client

func init() {
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// Allow for insecure clients (poc/testing purposes)
				InsecureSkipVerify: strings.ToLower(os.Getenv("HTTP_CLIENT_INSECURE")) == "true",
			},
		},
	}
}

func New(endpoint string) *Client {
	return &Client{
		endpoint: endpoint,
		keys: cache{
			kv:  make(map[string]interface{}),
			mtx: &sync.RWMutex{},
		},
	}
}

type Client struct {
	endpoint string
	keys     cache
}

func (c *Client) GetKey(kid string) (interface{}, error) {
	key, ok := c.keys.get(kid)
	if !ok {
		if err := c.updateCache(); err != nil {
			return nil, err
		}
	}

	key, ok = c.keys.get(kid)
	if !ok {
		return nil, errors.New("unrecognized key id")
	}

	return key, nil
}

func (c *Client) updateCache() error {
	ks, err := fetchJWKs(c.endpoint)
	if err != nil {
		return err
	}

	for _, k := range ks {
		c.keys.put(k.KeyID, k.Key)
	}

	return nil
}

func fetchJWKs(origin string) ([]jose.JsonWebKey, error) {
	var ks jose.JsonWebKeySet

	resp, err := httpClient.Get(origin)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&ks); err != nil {
		return nil, err
	}

	return ks.Keys, nil
}

type cache struct {
	kv  map[string]interface{}
	mtx *sync.RWMutex
}

func (c *cache) get(k string) (interface{}, bool) {
	c.mtx.RLock()
	v, ok := c.kv[k]
	c.mtx.RUnlock()
	return v, ok
}

func (c *cache) put(k string, v interface{}) {
	c.mtx.Lock()
	c.kv[k] = v
	c.mtx.Unlock()
}
