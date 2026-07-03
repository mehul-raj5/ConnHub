package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SupabaseConfig holds the credentials the chat server uses to mint signed
// upload/download URLs against a Supabase Storage bucket. Only the server holds
// these secrets; clients never see the service key.
type SupabaseConfig struct {
	URL        string // e.g. https://<project>.supabase.co
	ServiceKey string // service_role key
	Bucket     string // storage bucket name
}

func (c SupabaseConfig) Enabled() bool {
	return c.URL != "" && c.ServiceKey != "" && c.Bucket != ""
}

var mediaHTTP = &http.Client{Timeout: 30 * time.Second}

func (c SupabaseConfig) auth(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.ServiceKey)
	req.Header.Set("apikey", c.ServiceKey)
}

// SignUpload requests a signed upload URL for objectPath and returns the full
// URL the client should PUT the encrypted blob to.
func (c SupabaseConfig) SignUpload(objectPath string) (string, error) {
	endpoint := fmt.Sprintf("%s/storage/v1/object/upload/sign/%s/%s", c.URL, c.Bucket, objectPath)
	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return "", err
	}
	c.auth(req)

	resp, err := mediaHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("sign upload failed: %d %s", resp.StatusCode, string(body))
	}

	var out struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("sign upload decode: %w", err)
	}
	if out.URL == "" {
		return "", fmt.Errorf("sign upload: empty url in response")
	}
	return c.absolute(out.URL), nil
}

// absolute turns a relative storage path (e.g. "/object/sign/...") into a full
// URL; pass-through if the API already returned an absolute URL.
func (c SupabaseConfig) absolute(u string) string {
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	return c.URL + "/storage/v1" + u
}

// SignDownload requests a signed download URL for objectPath valid for ttlSeconds.
func (c SupabaseConfig) SignDownload(objectPath string, ttlSeconds int) (string, error) {
	endpoint := fmt.Sprintf("%s/storage/v1/object/sign/%s/%s", c.URL, c.Bucket, objectPath)
	payload, _ := json.Marshal(map[string]int{"expiresIn": ttlSeconds})
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	c.auth(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := mediaHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("sign download failed: %d %s", resp.StatusCode, string(body))
	}

	var out struct {
		SignedURL string `json:"signedURL"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("sign download decode: %w", err)
	}
	if out.SignedURL == "" {
		return "", fmt.Errorf("sign download: empty signedURL in response")
	}
	return c.absolute(out.SignedURL), nil
}
