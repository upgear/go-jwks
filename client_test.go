package jwks

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Example data taken from RFC 7517
		w.Write([]byte(`
{"keys":
   [
	 {"kty":"EC",
	  "crv":"P-256",
	  "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
	  "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	  "use":"enc",
	  "kid":"1"},

	 {"kty":"RSA",
	  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	  "e":"AQAB",
	  "alg":"RS256",
	  "kid":"2011-04-29"}
   ]
 }`))
	}))

	c, err := NewClient(ts.URL)
	assert.NoError(t, err)

	_, err = c.GetKey("2011-04-29")
	assert.NoError(t, err)

	_, err = c.GetKey("doesn't exist")
	assert.EqualError(t, err, "unrecognized key id")
}
