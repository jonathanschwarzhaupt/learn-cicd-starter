package auth

import (
	"errors"
	"github.com/google/go-cmp/cmp"
	"log"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		input       http.Header
		want_return string
		want_err    error
	}{
		"incorrect auth header":      {input: http.Header{"Authentication": []string{}}, want_return: "", want_err: ErrNoAuthHeaderIncluded},
		"auth header lowercase":      {input: http.Header{"authorization": []string{}}, want_return: "", want_err: ErrNoAuthHeaderIncluded},
		"empty api key":              {input: http.Header{"Authorization": []string{}}, want_return: "", want_err: ErrNoAuthHeaderIncluded},
		"api key single string":      {input: http.Header{"Authorization": []string{"api_key"}}, want_return: "", want_err: ErrMalformedAuthHeader},
		"api key single , separator": {input: http.Header{"Authorization": []string{"api, key"}}, want_return: "", want_err: ErrMalformedAuthHeader},
		"api key lowercase both":     {input: http.Header{"Authorization": []string{"apikey secretkey"}}, want_return: "", want_err: ErrMalformedAuthHeader},
		"api key lowercase one-1":    {input: http.Header{"Authorization": []string{"Apikey secretkey"}}, want_return: "", want_err: ErrMalformedAuthHeader},
		"api key lowercase one-2":    {input: http.Header{"Authorization": []string{"apiKey secretkey"}}, want_return: "", want_err: ErrMalformedAuthHeader},
		"correct":                    {input: http.Header{"Authorization": []string{"ApiKey secretkey"}}, want_return: "secretkey", want_err: nil},
		"correct key with two parts": {input: http.Header{"Authorization": []string{"ApiKey secretkey anotherone"}}, want_return: "secretkey", want_err: nil},
		"correct key but no value":   {input: http.Header{"Authorization": []string{"ApiKey"}}, want_return: "", want_err: ErrMalformedAuthHeader},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.input)
			diffRes := cmp.Diff(tc.want_return, got)
			if diffRes != "" {
				log.Fatal(diffRes)
			}
			if !errors.Is(tc.want_err, err) {
				log.Fatalf("returned error different for: %s. Expected: %v, got: %v", name, tc.want_err, err)
			}
		})
	}
}
