package globacl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(baseURL string, opts ...ClientOption) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		return nil, fmt.Errorf("globacl: base URL is required")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("globacl: invalid base URL: %w", err)
	}

	client := &Client{
		baseURL:    baseURL,
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(client)
	}
	if client.httpClient == nil {
		client.httpClient = http.DefaultClient
	}
	return client, nil
}

type ClientOption func(*Client)

func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(client *Client) {
		client.httpClient = httpClient
	}
}

func (client *Client) Deny(ctx context.Context, request DenyMutationRequest) (*CommitOutcomeResponse, error) {
	var response CommitOutcomeResponse
	if err := client.doJSON(ctx, http.MethodPost, "/v1/deny", request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (client *Client) Rule(ctx context.Context, request RuleMutationRequest) (*CommitOutcomeResponse, error) {
	var response CommitOutcomeResponse
	if err := client.doJSON(ctx, http.MethodPost, "/v1/rule", request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (client *Client) Lookup(ctx context.Context, tenantID, namespace, key string) (*DecisionResponse, error) {
	params := url.Values{}
	params.Set("tenant_id", tenantID)
	params.Set("namespace", namespace)
	params.Set("key", key)

	var response DecisionResponse
	if err := client.doJSON(ctx, http.MethodGet, "/v1/lookup?"+params.Encode(), nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (client *Client) Check(ctx context.Context, tenantID, namespace, value string) (*DecisionResponse, error) {
	params := url.Values{}
	params.Set("tenant_id", tenantID)
	params.Set("namespace", namespace)
	params.Set("value", value)

	var response DecisionResponse
	if err := client.doJSON(ctx, http.MethodGet, "/v1/check?"+params.Encode(), nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (client *Client) Watermarks(ctx context.Context) (*WatermarksResponse, error) {
	var response WatermarksResponse
	if err := client.doJSON(ctx, http.MethodGet, "/v1/watermarks", nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (client *Client) Snapshot(ctx context.Context) ([]byte, error) {
	return client.doBytes(ctx, http.MethodGet, "/v1/snapshot")
}

func (client *Client) Mutations(ctx context.Context, shard uint16, fromSeq uint64) ([]byte, error) {
	params := url.Values{}
	params.Set("shard", fmt.Sprintf("%d", shard))
	params.Set("from_seq", fmt.Sprintf("%d", fromSeq))
	return client.doBytes(ctx, http.MethodGet, "/v1/mutations?"+params.Encode())
}

func (client *Client) doJSON(ctx context.Context, method, path string, requestBody any, responseBody any) error {
	var body io.Reader
	if requestBody != nil {
		payload, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("globacl: encode request: %w", err)
		}
		body = bytes.NewReader(payload)
	}

	request, err := http.NewRequestWithContext(ctx, method, client.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("globacl: build request: %w", err)
	}
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Accept", "application/json")

	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("globacl: request failed: %w", err)
	}
	defer response.Body.Close()

	payload, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("globacl: read response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return APIError{StatusCode: response.StatusCode, Body: payload}
	}
	if responseBody == nil {
		return nil
	}
	if err := json.Unmarshal(payload, responseBody); err != nil {
		return fmt.Errorf("globacl: decode response: %w", err)
	}
	return nil
}

func (client *Client) doBytes(ctx context.Context, method, path string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, client.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("globacl: build request: %w", err)
	}
	request.Header.Set("Accept", "application/octet-stream")

	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("globacl: request failed: %w", err)
	}
	defer response.Body.Close()

	payload, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("globacl: read response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, APIError{StatusCode: response.StatusCode, Body: payload}
	}
	return payload, nil
}

type APIError struct {
	StatusCode int
	Body       []byte
}

func (err APIError) Error() string {
	return fmt.Sprintf("globacl: API returned status %d: %s", err.StatusCode, string(err.Body))
}
