package model_test

import (
	"auth-server/internal/model"
	"testing"
)

func TestAuthClientIsNotPublic(t *testing.T) {
	c := &model.AuthClient{
		ID:     1,
		Secret: "test-secret",
	}
	if c.IsPublic() {
		t.Fatal("AuthClient.IsPublic() should return false to enforce client secret validation")
	}
}

func TestAuthClientGetID(t *testing.T) {
	c := &model.AuthClient{
		ID:     42,
		Secret: "s",
	}
	if c.GetID() != "42" {
		t.Fatalf("expected '42', got '%s'", c.GetID())
	}
}

func TestAuthClientGetSecret(t *testing.T) {
	c := &model.AuthClient{
		ID:     1,
		Secret: "my-secret",
	}
	if c.GetSecret() != "my-secret" {
		t.Fatalf("expected 'my-secret', got '%s'", c.GetSecret())
	}
}
