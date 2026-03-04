package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Client polls the Okta System Log API.
// SECURITY: Token is never logged. Use redacted logging.
type Client struct {
	baseURL    string
	httpClient *http.Client
	// token is the Okta SSWS API token. NEVER log this value.
	token string
}

// SystemLogEvent is a minimal representation of an Okta System Log event.
type SystemLogEvent struct {
	UUID           string      `json:"uuid"`
	Published      time.Time   `json:"published"`
	EventType      string      `json:"eventType"`
	DisplayMessage string      `json:"displayMessage"`
	Severity       string      `json:"severity"`
	Actor          Actor       `json:"actor"`
	Outcome        Outcome     `json:"outcome"`
	Client         ClientInfo  `json:"client"`
	AuthContext    AuthContext `json:"authenticationContext"`
	Target         []Target    `json:"target"`
	Transaction    Transaction `json:"transaction"`
	Request        Request     `json:"request"`
}

type Actor struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	AlternateID string `json:"alternateId"` // PII
	DisplayName string `json:"displayName"`
}

type Outcome struct {
	Result string `json:"result"`
	Reason string `json:"reason"`
}

type ClientInfo struct {
	IPAddress           string     `json:"ipAddress"` // PII
	UserAgent           UserAgent  `json:"userAgent"`
	Zone                string     `json:"zone"`
	GeographicalContext GeoContext `json:"geographicalContext"`
}

type UserAgent struct {
	RawUserAgent string `json:"rawUserAgent"`
}

type GeoContext struct {
	City    string  `json:"city"`
	Country string  `json:"country"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

type AuthContext struct {
	AuthenticationProvider string `json:"authenticationProvider"`
	CredentialType         string `json:"credentialType"`
}

type Target struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	AlternateID string `json:"alternateId"` // PII
}

type Transaction struct {
	ID string `json:"id"`
}

type Request struct {
	IPChain []IPAddress `json:"ipChain"`
}

type IPAddress struct {
	IP string `json:"ip"` // PII
}

// NewClient creates a new Okta System Log polling client.
// SECURITY: token must never be logged.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// PollSystemLog fetches system log events since the given since time.
// Returns events, the next link (for pagination), and any error.
// SECURITY: Never log the Authorization header.
func (c *Client) PollSystemLog(ctx context.Context, since time.Time, limit int) ([]SystemLogEvent, string, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	params := url.Values{}
	params.Set("since", since.UTC().Format(time.RFC3339))
	params.Set("limit", strconv.Itoa(limit))
	params.Set("sortOrder", "ASCENDING")

	endpoint := fmt.Sprintf("%s/api/v1/logs?%s", c.baseURL, params.Encode())
	return c.fetchPage(ctx, endpoint)
}

// FetchPage fetches a specific page by URL (for pagination via Link header).
func (c *Client) FetchPage(ctx context.Context, pageURL string) ([]SystemLogEvent, string, error) {
	return c.fetchPage(ctx, pageURL)
}

func (c *Client) fetchPage(ctx context.Context, endpoint string) ([]SystemLogEvent, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", fmt.Errorf("okta client: create request: %w", err)
	}

	// SECURITY: Authorization header is never logged
	req.Header.Set("Authorization", "SSWS "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("okta client: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, "", &RateLimitError{RetryAfter: parseRetryAfter(resp)}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("okta client: unexpected status %d", resp.StatusCode)
	}

	var events []SystemLogEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, "", fmt.Errorf("okta client: decode response: %w", err)
	}

	// Extract next page link
	nextLink := extractNextLink(resp.Header.Get("Link"))
	return events, nextLink, nil
}

func parseRetryAfter(resp *http.Response) time.Duration {
	_ = resp.Header.Get("X-Rate-Limit-Reset")
	return 60 * time.Second
}

func extractNextLink(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}
	for _, part := range splitLink(linkHeader) {
		if len(part) < 2 {
			continue
		}
		linkURL := ""
		isNext := false
		for _, seg := range splitSemicolon(part) {
			seg = trimSpace(seg)
			if len(seg) > 2 && seg[0] == '<' && seg[len(seg)-1] == '>' {
				linkURL = seg[1 : len(seg)-1]
			}
			if seg == `rel="next"` {
				isNext = true
			}
		}
		if isNext && linkURL != "" {
			return linkURL
		}
	}
	return ""
}

func splitLink(s string) []string {
	var parts []string
	current := ""
	for _, ch := range s {
		if ch == ',' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func splitSemicolon(s string) []string {
	var parts []string
	current := ""
	for _, ch := range s {
		if ch == ';' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func trimSpace(s string) string {
	result := ""
	for i, ch := range s {
		if ch != ' ' && ch != '\t' {
			result = s[i:]
			break
		}
	}
	for len(result) > 0 {
		last := result[len(result)-1]
		if last == ' ' || last == '\t' {
			result = result[:len(result)-1]
		} else {
			break
		}
	}
	return result
}
