package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestMalformedHeader(t *testing.T) {
	malformedHeader := http.Header{}
	malformedHeader.Set("Authorization", "Bearer my-secret-key")
	got, err := GetAPIKey(malformedHeader)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Fatalf("expected error: %v, got: %v", "malformed authorization header", err)
	}
	if got != "" { // Ensure `got` is used
		t.Fatalf("expected empty string, got %s", got)
	}
}

func TestNoAuthHeader(t *testing.T) {
	noAuthHeader := http.Header{}
	got, err := GetAPIKey(noAuthHeader)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got != "" {
		t.Fatalf("expected empty string, got %s", got)
	}
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Fatalf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestValidHeader(t *testing.T) {
	correctHeader := http.Header{}
	correctHeader.Set("Authorization", "ApiKey my-secret-key")
	got, err := GetAPIKey(correctHeader)
	want := "my-secret-key"
	if err != nil || got != want {
		t.Fatalf("expected: %v, got: %v, error: %v", want, got, err)
	}

}

func TestMisspelledHeader(t *testing.T) {
	misspelledHeader := http.Header{}
	misspelledHeader.Set("Authorzation", "ApiKey my-secret-key")
	got, err := GetAPIKey(misspelledHeader)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got != "" {
		t.Fatalf("expected empty string, got %s", got)
	}
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Fatalf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestMissingAPIKey(t *testing.T) {

	missingKeyHeader := http.Header{}
	missingKeyHeader.Set("Authorization", "ApiKey")
	got, err := GetAPIKey(missingKeyHeader)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Fatalf("expected error: %v, got: %v", "malformed authorization header", err)
	}
	if got != "" {
		t.Fatalf("expected empty string, got %s", got)
	}

}

func TestEmptyAuthHeaderValue(t *testing.T) {
	emptyHeader := http.Header{}
	emptyHeader.Set("Authorization", "")
	got, err := GetAPIKey(emptyHeader)
	if err == nil || err.Error() != "no authorization header included" {
		t.Fatalf("expected error: %v, got: %v", "no authorization header included", err)
	}
	if got != "" {
		t.Fatalf("expected empty string, got %s", got)
	}
}
