// Package executor_test contains unit tests for the enforcement executor.
package executor_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"go.uber.org/zap"

	casespb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/cases"
	globalaudit "github.com/ethicaltomas/aitc/internal/audit"
	internalpolicy "github.com/ethicaltomas/aitc/internal/policy"
	oktaclient "github.com/ethicaltomas/aitc/internal/okta"
	"github.com/ethicaltomas/aitc/services/enforcement_okta/internal/executor"
)

// newTestPolicy writes temporary JSON policy files and returns a Loader.
func newTestPolicy(t *testing.T) *internalpolicy.Loader {
	t.Helper()
	allowlist := `{"version":"v1","global_allowed":["revoke_sessions","mfa_stepup","signon_policy_adjust"],"tenant_overrides":{}}`
	disallowed := `{"version":"v1","disallowed":["delete_account","disable_account","isolate_device","change_firewall_rule","bulk_user_policy_mutation"]}`

	alFile := writeTempFile(t, allowlist)
	daFile := writeTempFile(t, disallowed)

	loader, err := internalpolicy.LoadPolicies(alFile, daFile)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	return loader
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "policy-*.json")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	_ = f.Close()
	return f.Name()
}

// TestExecutor_DisallowedAction_HardBlock verifies that permanently disallowed actions
// are rejected without any Okta API call.
func TestExecutor_DisallowedAction_HardBlock(t *testing.T) {
	pol := newTestPolicy(t)
	logger := zap.NewNop()

	// Okta server that should NOT be called for disallowed actions
	callCount := 0
	oktaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer oktaSrv.Close()

	okta := oktaclient.NewClient(oktaSrv.URL, "test-token")
	// nil db is OK — disallowed check happens before DB access
	exec := executor.NewExecutor(nil, okta, pol, &globalaudit.Writer{}, logger)

	disallowedTypes := []string{
		"delete_account",
		"disable_account",
		"isolate_device",
		"change_firewall_rule",
		"bulk_user_policy_mutation",
	}

	for _, actionType := range disallowedTypes {
		t.Run(actionType, func(t *testing.T) {
			action := &casespb.ResponseActionV1{
				ActionId:       "action-001",
				TenantId:       "tenant-test",
				ActionType:     actionType,
				IdempotencyKey: "key-001",
			}
			err := exec.Dispatch(context.Background(), action)
			if err == nil {
				t.Errorf("expected error for disallowed action %q, got nil", actionType)
			}
		})
	}

	if callCount > 0 {
		t.Errorf("Okta API should not be called for disallowed actions; got %d calls", callCount)
	}
}

// TestExecutor_UnknownAction_Blocked verifies actions not in the allowlist are rejected.
func TestExecutor_UnknownAction_Blocked(t *testing.T) {
	pol := newTestPolicy(t)
	logger := zap.NewNop()
	okta := oktaclient.NewClient("http://localhost", "test-token")
	exec := executor.NewExecutor(nil, okta, pol, &globalaudit.Writer{}, logger)

	action := &casespb.ResponseActionV1{
		ActionId:       "action-002",
		TenantId:       "tenant-test",
		ActionType:     "send_email", // not in allowlist
		IdempotencyKey: "key-002",
	}
	err := exec.Dispatch(context.Background(), action)
	if err == nil {
		t.Error("expected error for unknown action type, got nil")
	}
}

// TestExecutor_AllowedActions_AreOnlyThreeTypes verifies the allowlist contains
// exactly the three safe action types.
func TestExecutor_AllowedActions_AreOnlyThreeTypes(t *testing.T) {
	pol := newTestPolicy(t)

	allowed := []string{"revoke_sessions", "mfa_stepup", "signon_policy_adjust"}
	for _, a := range allowed {
		if !pol.IsAllowed("tenant-test", a) {
			t.Errorf("expected %q to be allowed", a)
		}
	}

	notAllowed := []string{
		"delete_account", "disable_account", "isolate_device",
		"change_firewall_rule", "bulk_user_policy_mutation",
		"send_email", "export_data",
	}
	for _, a := range notAllowed {
		if pol.IsAllowed("tenant-test", a) {
			t.Errorf("expected %q to NOT be allowed", a)
		}
	}
}
