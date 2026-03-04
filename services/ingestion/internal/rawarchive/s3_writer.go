package rawarchive

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

// Archiver persists raw event payloads and returns the storage key and sha256 hash.
// Implementations must be safe for concurrent use.
type Archiver interface {
	// Archive stores payload and returns (s3Key, sha256hex, error).
	// The key is partitioned by tenant/source/date/hour for efficient retrieval.
	Archive(ctx context.Context, tenantID, source, eventID string, occurredAt time.Time, payload []byte) (s3Key string, hashHex string, err error)
}

// ComputeSHA256 returns the lowercase hex-encoded SHA-256 hash of data.
func ComputeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// buildKey returns a deterministic S3 key for the given event.
// Format: raw/<tenantID>/<source>/<YYYY>/<MM>/<DD>/<HH>/<eventID>.json
// This partitioning supports efficient Athena/Glue queries and lifecycle policies.
func buildKey(tenantID, source, eventID string, occurredAt time.Time) string {
	t := occurredAt.UTC()
	return path.Join(
		"raw",
		tenantID,
		source,
		fmt.Sprintf("%04d", t.Year()),
		fmt.Sprintf("%02d", t.Month()),
		fmt.Sprintf("%02d", t.Day()),
		fmt.Sprintf("%02d", t.Hour()),
		eventID+".json",
	)
}

// S3Writer writes raw event payloads to an S3-compatible store (AWS S3 or MinIO).
// Authentication uses AWS Signature Version 4.
//
// SSE (Server-Side Encryption):
//   In production set S3 bucket policies to enforce SSE-S3 or SSE-KMS at the bucket
//   level so that all objects are encrypted at rest without per-request headers.
//   For explicit per-request SSE-S3, add header "x-amz-server-side-encryption: AES256".
type S3Writer struct {
	httpClient *http.Client
	endpoint   string // e.g. "http://localhost:9000" for MinIO, "" for AWS S3
	bucket     string
	region     string
	accessKey  string
	secretKey  string
	pathStyle  bool // true for MinIO; false for virtual-hosted AWS S3
}

// NewS3Writer creates an S3Writer for S3-compatible storage.
// For MinIO in dev set endpoint to the MinIO server URL and pathStyle to true.
// For AWS S3 set endpoint to "" and pathStyle to false.
// SECURITY: accessKey/secretKey must never be logged.
func NewS3Writer(endpoint, bucket, region, accessKey, secretKey string, pathStyle bool) *S3Writer {
	return &S3Writer{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		endpoint:   strings.TrimRight(endpoint, "/"),
		bucket:     bucket,
		region:     region,
		accessKey:  accessKey,
		secretKey:  secretKey,
		pathStyle:  pathStyle,
	}
}

// Archive stores payload in S3/MinIO and returns the object key and sha256 hash.
func (w *S3Writer) Archive(ctx context.Context, tenantID, source, eventID string, occurredAt time.Time, payload []byte) (string, string, error) {
	key := buildKey(tenantID, source, eventID, occurredAt)
	hashHex := ComputeSHA256(payload)

	if err := w.putObject(ctx, key, payload, hashHex); err != nil {
		return "", "", fmt.Errorf("rawarchive: put object %q: %w", key, err)
	}
	return key, hashHex, nil
}

// putObject uploads data to S3 using a signed HTTP PUT request (AWS Sig V4).
func (w *S3Writer) putObject(ctx context.Context, key string, data []byte, hashHex string) error {
	url := w.buildURL(key)

	now := time.Now().UTC()
	dateStamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", hashHex)
	req.Header.Set("Host", req.URL.Host)

	// Build and set the AWS Signature V4 Authorization header.
	// SECURITY: secretKey is never logged or included in request body.
	authHeader := w.sigV4Auth(req, data, hashHex, dateStamp, amzDate)
	req.Header.Set("Authorization", authHeader)

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http put: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// buildURL constructs the PutObject URL for path-style (MinIO) or virtual-hosted (AWS S3).
func (w *S3Writer) buildURL(key string) string {
	if w.endpoint != "" {
		// MinIO / path-style: http://host/bucket/key
		return fmt.Sprintf("%s/%s/%s", w.endpoint, w.bucket, key)
	}
	// AWS S3 virtual-hosted: https://bucket.s3.region.amazonaws.com/key
	return fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", w.bucket, w.region, key)
}

// sigV4Auth computes the AWS Signature Version 4 Authorization header value.
// Reference: https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
func (w *S3Writer) sigV4Auth(req *http.Request, payload []byte, payloadHash, dateStamp, amzDate string) string {
	service := "s3"

	// Step 1: Canonical request
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		req.URL.Host, payloadHash, amzDate)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"

	canonicalPath := req.URL.EscapedPath()
	if canonicalPath == "" {
		canonicalPath = "/"
	}
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalPath,
		"", // query string (empty for PutObject)
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	// Step 2: String to sign
	credentialScope := strings.Join([]string{dateStamp, w.region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	// Step 3: Derive signing key and compute signature
	signingKey := deriveSigningKey(w.secretKey, dateStamp, w.region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	// Step 4: Assemble Authorization header
	return fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s,SignedHeaders=%s,Signature=%s",
		w.accessKey, credentialScope, signedHeaders, signature)
}

func hexSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func deriveSigningKey(secret, date, region, service string) []byte {
	kSecret := []byte("AWS4" + secret)
	kDate := hmacSHA256(kSecret, []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

// NoopArchiver discards payloads. Useful for testing or when archiving is disabled.
type NoopArchiver struct{}

func (NoopArchiver) Archive(_ context.Context, tenantID, source, eventID string, occurredAt time.Time, payload []byte) (string, string, error) {
	key := buildKey(tenantID, source, eventID, occurredAt)
	hashHex := ComputeSHA256(payload)
	return key, hashHex, nil
}

