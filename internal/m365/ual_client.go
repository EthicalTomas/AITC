package m365

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const (
	authURL    = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	scope      = "https://manage.office.com/.default"
	uALURL     = "https://manage.office.com/api/v1.0/%s/activity/feed/subscriptions/content"
	contentURL = "https://manage.office.com/api/v1.0/%s/activity/feed/audit/%s"
)

// Client polls the Microsoft 365 Unified Audit Log.
// SECURITY: ClientSecret is never logged.
type Client struct {
	tenantID     string
	clientID     string
	// clientSecret is sensitive - NEVER log. Load from Secrets Manager in prod.
	clientSecret string
	httpClient   *http.Client
	accessToken  string
	tokenExpiry  time.Time
}

// UALRecord is a minimal representation of a UAL audit record.
type UALRecord struct {
	ID             string    `json:"Id"`
	CreationTime   time.Time `json:"CreationTime"`
	Operation      string    `json:"Operation"`
	OrganizationId string    `json:"OrganizationId"`
	RecordType     int       `json:"RecordType"`
	ResultStatus   string    `json:"ResultStatus"`
	UserID         string    `json:"UserId"` // PII
	UserType       int       `json:"UserType"`
	Workload       string    `json:"Workload"`
	ObjectId       string    `json:"ObjectId"`
	ClientIP       string    `json:"ClientIP"` // PII
}

// ContentBlob is a reference to a content blob in the UAL feed.
type ContentBlob struct {
	ContentID         string    `json:"contentId"`
	ContentType       string    `json:"contentType"`
	ContentCreated    time.Time `json:"contentCreated"`
	ContentExpiration time.Time `json:"contentExpiration"`
	ContentURI        string    `json:"contentUri"`
}

// NewClient creates a new M365 UAL client.
// SECURITY: clientSecret must never be logged.
func NewClient(tenantID, clientID, clientSecret string) *Client {
	return &Client{
		tenantID:     tenantID,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ensureToken fetches or refreshes the access token.
// SECURITY: access token is never logged.
func (c *Client) ensureToken(ctx context.Context) error {
	if time.Now().Before(c.tokenExpiry.Add(-60 * time.Second)) {
		return nil
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.clientID)
	// SECURITY: client_secret never logged
	form.Set("client_secret", c.clientSecret)
	form.Set("scope", scope)

	tokenEndpoint := fmt.Sprintf(authURL, c.tenantID)
	resp, err := http.PostForm(tokenEndpoint, form)
	if err != nil {
		return fmt.Errorf("m365 client: token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("m365 client: token error status %d", resp.StatusCode)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("m365 client: decode token: %w", err)
	}

	// SECURITY: token is stored in memory only
	c.accessToken = result.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	return nil
}

// ListContentBlobs lists available content blobs for the given time range and content type.
func (c *Client) ListContentBlobs(ctx context.Context, contentType string, start, end time.Time) ([]ContentBlob, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Set("contentType", contentType)
	params.Set("startTime", start.UTC().Format("2006-01-02T15:04:05"))
	params.Set("endTime", end.UTC().Format("2006-01-02T15:04:05"))

	endpoint := fmt.Sprintf(uALURL, c.tenantID) + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("m365 client: create request: %w", err)
	}
	// SECURITY: Authorization header is never logged
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("m365 client: list blobs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("m365 client: list blobs status %d", resp.StatusCode)
	}

	var blobs []ContentBlob
	if err := json.NewDecoder(resp.Body).Decode(&blobs); err != nil {
		return nil, fmt.Errorf("m365 client: decode blobs: %w", err)
	}
	return blobs, nil
}

// FetchContent downloads records from a content blob URI.
func (c *Client) FetchContent(ctx context.Context, contentURI string) ([]UALRecord, error) {
	// SECURITY: Validate contentURI host is the expected M365 host to prevent SSRF.
	// contentURI comes from external API responses and must not be trusted blindly.
	parsed, parseErr := url.Parse(contentURI)
	if parseErr != nil || parsed.Scheme != "https" || parsed.Host != "manage.office.com" {
		return nil, fmt.Errorf("m365 client: contentURI must be https://manage.office.com/...")
	}
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, contentURI, nil)
	if err != nil {
		return nil, fmt.Errorf("m365 client: create content request: %w", err)
	}
	// SECURITY: Authorization header is never logged
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("m365 client: fetch content: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("m365 client: fetch content status %d", resp.StatusCode)
	}

	var records []UALRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return nil, fmt.Errorf("m365 client: decode content: %w", err)
	}
	return records, nil
}
