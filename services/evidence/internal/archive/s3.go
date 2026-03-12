// Package archive writes completed evidence reports to S3/MinIO and
// marks the corresponding evidence_reports row as complete.
//
// SECURITY: access key and secret key are never logged.
package archive

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ethicaltomas/aitc/internal/tenant"
)

// Uploader stores a report bundle in S3/MinIO and marks the DB row complete.
type Uploader struct {
	httpClient *http.Client
	endpoint   string // e.g. "http://localhost:9000" for MinIO; "" for AWS S3
	bucket     string
	region     string
	accessKey  string
	secretKey  string
	db         *pgxpool.Pool
}

// NewUploader creates an Uploader.
// For MinIO set endpoint to the server URL (path-style).
// For AWS S3 leave endpoint empty (virtual-hosted style).
// SECURITY: accessKey/secretKey must not be logged.
func NewUploader(endpoint, bucket, region, accessKey, secretKey string, db *pgxpool.Pool) *Uploader {
	return &Uploader{
		httpClient: &http.Client{Timeout: 60 * time.Second},
		endpoint:   strings.TrimRight(endpoint, "/"),
		bucket:     bucket,
		region:     region,
		accessKey:  accessKey,
		secretKey:  secretKey,
		db:         db,
	}
}

// Upload writes data to S3/MinIO at key and then updates the evidence_reports row
// identified by reportID + tenantID to status=complete with the stored bucket/key.
func (u *Uploader) Upload(ctx context.Context, tenantID, reportID, key string, data []byte) error {
	hashHex := hexSHA256(data)

	if err := u.putObject(ctx, key, data, hashHex); err != nil {
		return fmt.Errorf("archive: put object %q: %w", key, err)
	}

	if u.db != nil {
		if err := u.markComplete(ctx, tenantID, reportID, key); err != nil {
			return fmt.Errorf("archive: mark complete: %w", err)
		}
	}
	return nil
}

// BuildKey returns a deterministic S3 key for an evidence report.
// Format: reports/<tenantID>/<reportType>/<reportID>.json
func BuildKey(tenantID, reportType, reportID string) string {
	return fmt.Sprintf("reports/%s/%s/%s.json", tenantID, reportType, reportID)
}

// markComplete updates the evidence_reports row to status=complete and sets s3_key/s3_bucket.
func (u *Uploader) markComplete(ctx context.Context, tenantID, reportID, key string) error {
	tx, err := u.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := tenant.SetRLS(ctx, tx, tenantID); err != nil {
		return fmt.Errorf("set rls: %w", err)
	}

	_, err = tx.Exec(ctx,
		`UPDATE evidence_reports
		    SET status = 'complete', s3_key = $1, s3_bucket = $2, updated_at = NOW()
		  WHERE id = $3 AND tenant_id = $4`,
		key, u.bucket, reportID, tenantID)
	if err != nil {
		return fmt.Errorf("update evidence_reports: %w", err)
	}

	return tx.Commit(ctx)
}

// putObject uploads data to S3/MinIO via a signed HTTP PUT (AWS Sig V4).
func (u *Uploader) putObject(ctx context.Context, key string, data []byte, hashHex string) error {
	url := u.buildURL(key)

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

	// SECURITY: secretKey is never included in request body or logged.
	authHeader := u.sigV4Auth(req, hashHex, dateStamp, amzDate)
	req.Header.Set("Authorization", authHeader)

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http put: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close() //nolint:errcheck
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// buildURL constructs the PUT URL for path-style (MinIO) or virtual-hosted (AWS S3).
func (u *Uploader) buildURL(key string) string {
	if u.endpoint != "" {
		return fmt.Sprintf("%s/%s/%s", u.endpoint, u.bucket, key)
	}
	return fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", u.bucket, u.region, key)
}

// sigV4Auth computes the AWS Signature Version 4 Authorization header.
func (u *Uploader) sigV4Auth(req *http.Request, payloadHash, dateStamp, amzDate string) string {
	service := "s3"

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
		"",
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := strings.Join([]string{dateStamp, u.region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	signingKey := deriveSigningKey(u.secretKey, dateStamp, u.region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	return fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s,SignedHeaders=%s,Signature=%s",
		u.accessKey, credentialScope, signedHeaders, signature)
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

// NoopUploader discards data and does nothing (useful in unit tests).
type NoopUploader struct {
	Bucket string
}

// Upload records the key but does not write to S3 or DB.
func (n *NoopUploader) Upload(_ context.Context, _, _, key string, _ []byte) error {
	return nil
}

