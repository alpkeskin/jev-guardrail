package auth

import (
	"net/http/httptest"
	"testing"
)

func TestStaticKeys(t *testing.T) {
	keys, err := ParseStaticKeys("litellm:0123456789abcdef0123, fedcba9876543210fedc")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		header, want string
		ok           bool
	}{
		{"Bearer 0123456789abcdef0123", "litellm", true},
		{"bearer fedcba9876543210fedc", "key-2", true},
		{"Bearer wrong-key-wrong-key", "", false},
		{"0123456789abcdef0123", "", false},
		{"Basic 0123456789abcdef0123", "", false},
		{"Bearer ", "", false},
		{"", "", false},
	}
	for _, tc := range tests {
		r := httptest.NewRequest("POST", "/v1/guard", nil)
		if tc.header != "" {
			r.Header.Set("Authorization", tc.header)
		}
		caller, err := keys.Authenticate(r)
		if (err == nil) != tc.ok || caller != tc.want {
			t.Errorf("Authenticate(%q) = %q, %v", tc.header, caller, err)
		}
	}
}

func TestParseStaticKeysErrors(t *testing.T) {
	for _, spec := range []string{"", " , ", "short", "a:", ":0123456789abcdef", "a:0123456789abcdef,a:fedcba9876543210", "# a comment that is long enough", "name:0123456789 abcdef"} {
		if _, err := ParseStaticKeys(spec); err == nil {
			t.Errorf("ParseStaticKeys(%q) should fail", spec)
		}
	}
}

func TestClientIDIsNotAuthentication(t *testing.T) {
	keys, _ := ParseStaticKeys("0123456789abcdef0123")
	r := httptest.NewRequest("POST", "/v1/guard", nil)
	r.Header.Set("X-Client-ID", "0123456789abcdef0123")
	if _, err := keys.Authenticate(r); err == nil {
		t.Fatal("X-Client-ID must not authenticate")
	}
}
