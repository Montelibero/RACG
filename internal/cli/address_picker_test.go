package cli

import "testing"

func TestNormalizePublicURL(t *testing.T) {
	cases := []struct {
		in   string
		port int
		want string
	}{
		{"admin26.tail8add2.ts.net", 8777, "http://admin26.tail8add2.ts.net:8777"},
		{"100.68.196.60:9443", 8777, "http://100.68.196.60:9443"},
		{"https://racg.example.org", 8777, "https://racg.example.org:443"},
		{"http://server:8777/", 8777, "http://server:8777"},
	}
	for _, tc := range cases {
		if got := normalizePublicURL(tc.in, tc.port); got != tc.want {
			t.Fatalf("normalize(%q,%d)=%q want %q", tc.in, tc.port, got, tc.want)
		}
	}
}
