package web

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

// TestVerificationMandatoryPreviewBlocksRawCreate encodes the approved safety
// requirement that a customer mutation needs a valid signed preview token.
func TestVerificationMandatoryPreviewBlocksRawCreate(t *testing.T) {
	app := newTestWebApp(t)
	login(t, app)

	response := postForm(t, app, "/customers", url.Values{
		"name":     {"raw-review-bypass"},
		"networks": {"10.123.0.1"},
	})
	_ = readBody(t, response)
	if response.StatusCode < http.StatusBadRequest || response.StatusCode >= http.StatusInternalServerError {
		t.Fatalf("raw create status = %d, want a client rejection", response.StatusCode)
	}

	customers, err := app.repository.Customers(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(customers) != 0 {
		t.Fatalf("raw create persisted %d customer(s), want no write without a signed preview", len(customers))
	}
}
