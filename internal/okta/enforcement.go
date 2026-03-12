package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// UserSession represents a single Okta user session.
type UserSession struct {
	ID        string `json:"id"`
	Login     string `json:"login"`
	UserAgent string `json:"userAgent"`
	IPAddress string `json:"ipAddress"` // PII
}

// SignOnPolicyRule represents an Okta sign-on policy rule (subset of fields).
type SignOnPolicyRule struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Priority  int    `json:"priority"`
}

// RevokeUserSessions clears all active sessions for a user.
// Okta API: DELETE /api/v1/users/{userId}/sessions
// SECURITY: token is never logged.
func (c *Client) RevokeUserSessions(ctx context.Context, userID string) error {
	if userID == "" {
		return fmt.Errorf("okta enforcement: userID is required")
	}
	endpoint := fmt.Sprintf("%s/api/v1/users/%s/sessions", c.baseURL, url.PathEscape(userID))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("okta enforcement: create revoke-sessions request: %w", err)
	}
	req.Header.Set("Authorization", "SSWS "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("okta enforcement: revoke-sessions request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		return &RateLimitError{RetryAfter: parseRetryAfter(resp)}
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("okta enforcement: revoke-sessions unexpected status %d", resp.StatusCode)
	}
	return nil
}

// GetUserSessions returns active sessions for a user (used for before-state capture).
// Okta API: GET /api/v1/users/{userId}/sessions
func (c *Client) GetUserSessions(ctx context.Context, userID string) ([]UserSession, error) {
	if userID == "" {
		return nil, fmt.Errorf("okta enforcement: userID is required")
	}
	endpoint := fmt.Sprintf("%s/api/v1/users/%s/sessions", c.baseURL, url.PathEscape(userID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("okta enforcement: create get-sessions request: %w", err)
	}
	req.Header.Set("Authorization", "SSWS "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("okta enforcement: get-sessions request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, &RateLimitError{RetryAfter: parseRetryAfter(resp)}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("okta enforcement: get-sessions unexpected status %d", resp.StatusCode)
	}

	var sessions []UserSession
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		return nil, fmt.Errorf("okta enforcement: decode sessions: %w", err)
	}
	return sessions, nil
}

// ResetUserMFAFactors resets all enrolled MFA factors for a user, requiring re-enrollment.
// Okta API: POST /api/v1/users/{userId}/lifecycle/reset_factors
// SECURITY: This forces the user to re-enroll MFA — use only for confirmed threats.
func (c *Client) ResetUserMFAFactors(ctx context.Context, userID string) error {
	if userID == "" {
		return fmt.Errorf("okta enforcement: userID is required")
	}
	endpoint := fmt.Sprintf("%s/api/v1/users/%s/lifecycle/reset_factors", c.baseURL, url.PathEscape(userID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return fmt.Errorf("okta enforcement: create reset-factors request: %w", err)
	}
	req.Header.Set("Authorization", "SSWS "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("okta enforcement: reset-factors request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		return &RateLimitError{RetryAfter: parseRetryAfter(resp)}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("okta enforcement: reset-factors unexpected status %d", resp.StatusCode)
	}
	return nil
}

// GetUserEnrolledFactors retrieves the list of enrolled MFA factors for a user (before-state capture).
// Okta API: GET /api/v1/users/{userId}/factors
func (c *Client) GetUserEnrolledFactors(ctx context.Context, userID string) ([]map[string]interface{}, error) {
	if userID == "" {
		return nil, fmt.Errorf("okta enforcement: userID is required")
	}
	endpoint := fmt.Sprintf("%s/api/v1/users/%s/factors", c.baseURL, url.PathEscape(userID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("okta enforcement: create get-factors request: %w", err)
	}
	req.Header.Set("Authorization", "SSWS "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("okta enforcement: get-factors request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, &RateLimitError{RetryAfter: parseRetryAfter(resp)}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("okta enforcement: get-factors unexpected status %d", resp.StatusCode)
	}

	var factors []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&factors); err != nil {
		return nil, fmt.Errorf("okta enforcement: decode factors: %w", err)
	}
	return factors, nil
}

// GetSignOnPolicyRule retrieves the current state of a sign-on policy rule (before-state capture).
// Okta API: GET /api/v1/policies/{policyId}/rules/{ruleId}
func (c *Client) GetSignOnPolicyRule(ctx context.Context, policyID, ruleID string) (*SignOnPolicyRule, error) {
	if policyID == "" || ruleID == "" {
		return nil, fmt.Errorf("okta enforcement: policyID and ruleID are required")
	}
	endpoint := fmt.Sprintf("%s/api/v1/policies/%s/rules/%s",
		c.baseURL, url.PathEscape(policyID), url.PathEscape(ruleID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("okta enforcement: create get-policy-rule request: %w", err)
	}
	req.Header.Set("Authorization", "SSWS "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("okta enforcement: get-policy-rule request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, &RateLimitError{RetryAfter: parseRetryAfter(resp)}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("okta enforcement: get-policy-rule unexpected status %d", resp.StatusCode)
	}

	var rule SignOnPolicyRule
	if err := json.NewDecoder(resp.Body).Decode(&rule); err != nil {
		return nil, fmt.Errorf("okta enforcement: decode policy rule: %w", err)
	}
	return &rule, nil
}

// UpdateSignOnPolicyRule applies a scoped mutation to a sign-on policy rule.
// Only the provided patch fields are applied (partial update).
// Okta API: PUT /api/v1/policies/{policyId}/rules/{ruleId}
// GUARDRAIL: Bulk policy mutation is disallowed. This method only adjusts a single rule.
func (c *Client) UpdateSignOnPolicyRule(ctx context.Context, policyID, ruleID string, patch map[string]interface{}) error {
	if policyID == "" || ruleID == "" {
		return fmt.Errorf("okta enforcement: policyID and ruleID are required")
	}
	if len(patch) == 0 {
		return fmt.Errorf("okta enforcement: patch must not be empty")
	}

	body, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("okta enforcement: marshal patch: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/v1/policies/%s/rules/%s",
		c.baseURL, url.PathEscape(policyID), url.PathEscape(ruleID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("okta enforcement: create update-policy-rule request: %w", err)
	}
	req.Header.Set("Authorization", "SSWS "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("okta enforcement: update-policy-rule request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		return &RateLimitError{RetryAfter: parseRetryAfter(resp)}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("okta enforcement: update-policy-rule unexpected status %d", resp.StatusCode)
	}
	return nil
}
