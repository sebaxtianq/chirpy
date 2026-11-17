package auth

import (
	"net/http"
	"testing"
	"time"
	"uuid"
)

func TestCreateJWT(t *testing.T) {
	id, _ := uuid.Parse("dc19033e-62a6-4854-9b1d-31f57ee0e19c")
	h, _ := time.ParseDuration("4h30m")
	_, err := MakeJWT(id, "secret.Pass", time.Duration(h))
	if err != nil {
		t.Errorf("Error creating JWT %v for id %v", err, id)
	}
}

func TestValidateJWT(t *testing.T) {
	id, _ := uuid.Parse("dc19033e-62a6-4854-9b1d-31f57ee0e19c")
	h, _ := time.ParseDuration("4h30m")
	token, err := MakeJWT(id, "secret.Pass", time.Duration(h))
	if err != nil {
		t.Errorf("Error creating JWT %v for id %v", err, id)
	}
	returned_id, err := ValidateJWT(token, "secret.Pass")
	if returned_id != id {
		t.Errorf("Returned id error, expecting %v, returned %v", id, returned_id)
	}
	if err != nil {
		t.Errorf("Error validating JWT %v", err)
	}
}
func TestExpiredToken(t *testing.T) {
	id, _ := uuid.Parse("dc19033e-62a6-4854-9b1d-31f57ee0e19c")
	h, _ := time.ParseDuration("4h30m")
	token, err := MakeJWT(id, "secret.Pass", time.Duration(-h))
	if err != nil {
		t.Errorf("Error creating JWT %v for id %v", err, id)
	}
	_, err = ValidateJWT(token, "secret.Pass")
	if err == nil {
		t.Errorf("Expected error when validating expired token, got nil instead.")
	}
}
func TestGetToken(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer my-secret-token")
	token, err := GetBearerToken(headers)
	if err != nil {
		t.Errorf("Error extracting Token from Auth header")
	}
	if token != "my-secret-token" {
		t.Errorf("Unexpected token %v, was expecting %v", token, "my-secret-token")
	}
}
