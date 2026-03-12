// Package actions_test contains unit tests for enforcement actions.
package actions_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	oktaclient "github.com/ethicaltomas/aitc/internal/okta"
	"github.com/ethicaltomas/aitc/services/enforcement_okta/internal/actions"
)

// TestRevokeSessionsExecutor_MissingUserID verifies that missing user_id returns an error.
func TestRevokeSessionsExecutor_MissingUserID(t *testing.T) {
	okta := oktaclient.NewClient("http://localhost", "test-token")
	exec := actions.NewRevokeSessionsExecutor(okta, zap.NewNop())

	_, err := exec.Execute(context.Background(), `{}`)
	if err == nil {
		t.Error("expected error for missing user_id, got nil")
	}
}

// TestRevokeSessionsExecutor_InvalidJSON verifies that invalid parameters JSON returns an error.
func TestRevokeSessionsExecutor_InvalidJSON(t *testing.T) {
	okta := oktaclient.NewClient("http://localhost", "test-token")
	exec := actions.NewRevokeSessionsExecutor(okta, zap.NewNop())

	_, err := exec.Execute(context.Background(), `not-valid-json`)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// TestRevokeSessionsExecutor_Success verifies the action calls the Okta API and returns state.
func TestRevokeSessionsExecutor_Success(t *testing.T) {
	// Mock Okta server: GET sessions returns [], DELETE sessions returns 204
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	okta := oktaclient.NewClient(srv.URL, "test-token")
	exec := actions.NewRevokeSessionsExecutor(okta, zap.NewNop())

	result, err := exec.Execute(context.Background(), `{"user_id":"user-abc"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.BeforeState == nil || result.AfterState == nil {
		t.Error("expected non-nil before/after state")
	}
}

// TestMFAStepUpExecutor_MissingUserID verifies that missing user_id returns an error.
func TestMFAStepUpExecutor_MissingUserID(t *testing.T) {
	okta := oktaclient.NewClient("http://localhost", "test-token")
	exec := actions.NewMFAStepUpExecutor(okta, zap.NewNop())

	_, err := exec.Execute(context.Background(), `{}`)
	if err == nil {
		t.Error("expected error for missing user_id, got nil")
	}
}

// TestMFAStepUpExecutor_Success verifies the action calls the Okta API and returns state.
func TestMFAStepUpExecutor_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// GET factors
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":"factor-1","factorType":"token:software:totp"}]`))
		case http.MethodPost:
			// POST reset_factors
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	okta := oktaclient.NewClient(srv.URL, "test-token")
	exec := actions.NewMFAStepUpExecutor(okta, zap.NewNop())

	result, err := exec.Execute(context.Background(), `{"user_id":"user-abc"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// TestSignOnPolicyAdjustExecutor_MissingPolicyID verifies validation.
func TestSignOnPolicyAdjustExecutor_MissingPolicyID(t *testing.T) {
	okta := oktaclient.NewClient("http://localhost", "test-token")
	exec := actions.NewSignOnPolicyAdjustExecutor(okta, zap.NewNop())

	_, err := exec.Execute(context.Background(), `{"rule_id":"rule-1","patch":{"status":"ACTIVE"}}`)
	if err == nil {
		t.Error("expected error for missing policy_id, got nil")
	}
}

// TestSignOnPolicyAdjustExecutor_MissingRuleID verifies validation.
func TestSignOnPolicyAdjustExecutor_MissingRuleID(t *testing.T) {
	okta := oktaclient.NewClient("http://localhost", "test-token")
	exec := actions.NewSignOnPolicyAdjustExecutor(okta, zap.NewNop())

	_, err := exec.Execute(context.Background(), `{"policy_id":"policy-1","patch":{"status":"ACTIVE"}}`)
	if err == nil {
		t.Error("expected error for missing rule_id, got nil")
	}
}

// TestSignOnPolicyAdjustExecutor_EmptyPatch verifies that empty patch is rejected.
func TestSignOnPolicyAdjustExecutor_EmptyPatch(t *testing.T) {
	okta := oktaclient.NewClient("http://localhost", "test-token")
	exec := actions.NewSignOnPolicyAdjustExecutor(okta, zap.NewNop())

	_, err := exec.Execute(context.Background(), `{"policy_id":"policy-1","rule_id":"rule-1","patch":{}}`)
	if err == nil {
		t.Error("expected error for empty patch, got nil")
	}
}

// TestSignOnPolicyAdjustExecutor_Success verifies the action calls the Okta API.
func TestSignOnPolicyAdjustExecutor_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"rule-1","name":"Default Rule","status":"ACTIVE","priority":0}`))
		case http.MethodPut:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"rule-1","name":"Default Rule","status":"INACTIVE","priority":0}`))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	okta := oktaclient.NewClient(srv.URL, "test-token")
	exec := actions.NewSignOnPolicyAdjustExecutor(okta, zap.NewNop())

	params := `{"policy_id":"policy-1","rule_id":"rule-1","patch":{"status":"INACTIVE"}}`
	result, err := exec.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}
