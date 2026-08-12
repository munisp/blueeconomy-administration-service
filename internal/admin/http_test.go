package admin

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSONRejectsTrailingDocument(t *testing.T) {
	request := httptest.NewRequest("POST", "/", strings.NewReader(`{"decision":"approve"} {"decision":"reject"}`))
	var payload struct {
		Decision string `json:"decision"`
	}
	if err := decodeJSON(request, &payload); err == nil {
		t.Fatal("expected trailing JSON document to be rejected")
	}
}

func TestDecodeJSONRejectsUndeclaredField(t *testing.T) {
	request := httptest.NewRequest("POST", "/", strings.NewReader(`{"decision":"approve","unexpected":true}`))
	var payload struct {
		Decision string `json:"decision"`
	}
	if err := decodeJSON(request, &payload); err == nil {
		t.Fatal("expected undeclared JSON field to be rejected")
	}
}
