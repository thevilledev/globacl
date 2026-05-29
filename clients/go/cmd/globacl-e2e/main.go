package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/thevilledev/globacl/clients/go/globacl"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: globacl-e2e <wait-health|require-health-fields|deny|wait-demo-deny|wait-check-deny|wait-propagation|wait-prometheus-query|wait-grafana-dashboard>")
	}

	var err error
	switch os.Args[1] {
	case "wait-health":
		err = waitHealth(os.Args[2:])
	case "require-health-fields":
		err = requireHealthFields(os.Args[2:])
	case "deny":
		err = deny(os.Args[2:])
	case "wait-demo-deny":
		err = waitDemoDeny(os.Args[2:])
	case "wait-check-deny":
		err = waitCheckDeny(os.Args[2:])
	case "wait-propagation":
		err = waitPropagation(os.Args[2:])
	case "wait-prometheus-query":
		err = waitPrometheusQuery(os.Args[2:])
	case "wait-grafana-dashboard":
		err = waitGrafanaDashboard(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fatalf("%v", err)
	}
}

func waitHealth(args []string) error {
	flags := flag.NewFlagSet("wait-health", flag.ExitOnError)
	baseURL := flags.String("base-url", "", "component base URL")
	timeout := flags.Duration("timeout", 120*time.Second, "wait timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	client, err := newClient(*baseURL)
	if err != nil {
		return err
	}
	var lastErr error
	var lastStatus globacl.HealthResponseStatus
	var sawStatus bool
	err = waitUntil(*timeout, func(ctx context.Context) (bool, error) {
		health, err := client.Health(ctx)
		if err != nil {
			lastErr = err
			return false, nil
		}
		lastErr = nil
		lastStatus = health.Status
		sawStatus = true
		return health.Status == globacl.HealthResponseStatusOk ||
			health.Status == globacl.HealthResponseStatusDegraded ||
			health.Status == globacl.HealthResponseStatusStale, nil
	})
	if err == nil {
		return nil
	}
	if lastErr != nil {
		return fmt.Errorf("%w: last health error: %v", err, lastErr)
	}
	if sawStatus {
		return fmt.Errorf("%w: last health status: %q", err, lastStatus)
	}
	return err
}

func requireHealthFields(args []string) error {
	flags := flag.NewFlagSet("require-health-fields", flag.ExitOnError)
	baseURL := flags.String("base-url", "", "component base URL")
	fields := flags.String("fields", "", "comma-separated fields that must exist")
	timeout := flags.Duration("timeout", 120*time.Second, "wait timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*fields) == "" {
		return fmt.Errorf("--fields is required")
	}
	requiredFields := strings.Split(*fields, ",")
	client, err := newClient(*baseURL)
	if err != nil {
		return err
	}
	var lastErr error
	var lastMissing []string
	err = waitUntil(*timeout, func(ctx context.Context) (bool, error) {
		health, err := client.Health(ctx)
		if err != nil {
			lastErr = err
			return false, nil
		}
		lastErr = nil
		lastMissing = lastMissing[:0]
		for _, field := range requiredFields {
			name := strings.TrimSpace(field)
			if _, ok := health.Get(name); !ok {
				lastMissing = append(lastMissing, name)
			}
		}
		return len(lastMissing) == 0, nil
	})
	if err == nil {
		return nil
	}
	if lastErr != nil {
		return fmt.Errorf("%w: last health error: %v", err, lastErr)
	}
	if len(lastMissing) > 0 {
		return fmt.Errorf("%w: last missing health fields: %s", err, strings.Join(lastMissing, ","))
	}
	return err
}

func deny(args []string) error {
	flags := flag.NewFlagSet("deny", flag.ExitOnError)
	baseURL := flags.String("base-url", "", "control base URL")
	opID := flags.String("op-id", "", "operation id")
	tenantID := flags.String("tenant-id", "", "tenant id")
	namespace := flags.String("namespace", "", "namespace")
	key := flags.String("key", "", "key")
	reasonCode := flags.String("reason-code", "e2e", "reason code")
	createdBy := flags.String("created-by", "e2e", "creator")
	deliveryPriority := flags.String("delivery-priority", "p0", "delivery priority")
	if err := flags.Parse(args); err != nil {
		return err
	}
	client, err := newClient(*baseURL)
	if err != nil {
		return err
	}
	priority, err := deliveryPriorityValue(*deliveryPriority)
	if err != nil {
		return err
	}
	request := globacl.DenyMutationRequest{
		OpId:             requireValue("op-id", *opID),
		TenantId:         requireValue("tenant-id", *tenantID),
		Namespace:        requireValue("namespace", *namespace),
		Key:              requireValue("key", *key),
		Action:           globacl.ActionDeny,
		ReasonCode:       reasonCode,
		CreatedBy:        createdBy,
		DeliveryPriority: &priority,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	outcome, err := client.Deny(ctx, request)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(map[string]any{
		"status":    "committed",
		"shard_id":  outcome.ShardId,
		"seq":       outcome.Seq,
		"duplicate": outcome.Duplicate,
	})
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

func waitDemoDeny(args []string) error {
	flags := flag.NewFlagSet("wait-demo-deny", flag.ExitOnError)
	baseURL := flags.String("base-url", "", "demo app base URL")
	tenantID := flags.String("tenant-id", "", "tenant id")
	namespace := flags.String("namespace", "", "namespace")
	key := flags.String("key", "", "key")
	timeout := flags.Duration("timeout", 120*time.Second, "wait timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	base, err := normalizeBaseURL(*baseURL)
	if err != nil {
		return err
	}
	params := url.Values{}
	params.Set("tenant_id", requireValue("tenant-id", *tenantID))
	params.Set("namespace", requireValue("namespace", *namespace))
	params.Set("key", requireValue("key", *key))
	path := base + "/access?" + params.Encode()
	return waitUntil(*timeout, func(ctx context.Context) (bool, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		if err != nil {
			return false, err
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return false, nil
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return false, err
		}
		var payload struct {
			Access string `json:"access"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return false, nil
		}
		return response.StatusCode == http.StatusForbidden && payload.Access == "denied", nil
	})
}

func waitCheckDeny(args []string) error {
	flags := flag.NewFlagSet("wait-check-deny", flag.ExitOnError)
	baseURL := flags.String("base-url", "", "control base URL")
	tenantID := flags.String("tenant-id", "", "tenant id")
	namespace := flags.String("namespace", "", "namespace")
	key := flags.String("key", "", "key")
	timeout := flags.Duration("timeout", 120*time.Second, "wait timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	client, err := newClient(*baseURL)
	if err != nil {
		return err
	}
	var lastDecision string
	err = waitUntil(*timeout, func(ctx context.Context) (bool, error) {
		decision, err := client.Check(
			ctx,
			requireValue("tenant-id", *tenantID),
			requireValue("namespace", *namespace),
			requireValue("key", *key),
		)
		if err != nil {
			return false, nil
		}
		encoded, _ := json.Marshal(decision)
		lastDecision = string(encoded)
		deny, err := decision.AsDenyDecision()
		return err == nil && deny.Decision == globacl.DenyDecisionDecisionDeny, nil
	})
	if err != nil && lastDecision != "" {
		return fmt.Errorf("%w: last check decision %s", err, lastDecision)
	}
	return err
}

func waitPropagation(args []string) error {
	flags := flag.NewFlagSet("wait-propagation", flag.ExitOnError)
	baseURL := flags.String("base-url", "", "control base URL")
	expectedAgents := flags.Int64("expected-agents", 1, "minimum acked agents")
	timeout := flags.Duration("timeout", 120*time.Second, "wait timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	client, err := newClient(*baseURL)
	if err != nil {
		return err
	}
	var last *globacl.PropagationStatusResponse
	err = waitUntil(*timeout, func(ctx context.Context) (bool, error) {
		status, err := client.PropagationStatus(ctx)
		if err != nil {
			return false, nil
		}
		last = status
		return status.AgentCount >= *expectedAgents && status.MaxSeqLag == 0, nil
	})
	if err != nil && last != nil {
		encoded, _ := json.Marshal(last)
		return fmt.Errorf("%w: last propagation status %s", err, encoded)
	}
	return err
}

func waitPrometheusQuery(args []string) error {
	flags := flag.NewFlagSet("wait-prometheus-query", flag.ExitOnError)
	baseURL := flags.String("base-url", "", "Prometheus base URL")
	query := flags.String("query", "", "Prometheus instant query")
	minimum := flags.Float64("min", 1, "minimum accepted value")
	timeout := flags.Duration("timeout", 120*time.Second, "wait timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	normalized, err := normalizeBaseURL(*baseURL)
	if err != nil {
		return err
	}
	queryValue := requireValue("query", *query)

	var lastErr error
	var lastValue float64
	var sawValue bool
	err = waitUntil(*timeout, func(ctx context.Context) (bool, error) {
		value, ok, err := prometheusInstantValue(ctx, normalized, queryValue)
		if err != nil {
			lastErr = err
			return false, nil
		}
		if ok {
			lastValue = value
			sawValue = true
		}
		return ok && value >= *minimum, nil
	})
	if err == nil {
		return nil
	}
	if sawValue {
		return fmt.Errorf(
			"%w: last value %.6g for query %q was below %.6g",
			err,
			lastValue,
			queryValue,
			*minimum,
		)
	}
	if lastErr != nil {
		return fmt.Errorf("%w: last Prometheus error: %v", err, lastErr)
	}
	return fmt.Errorf("%w: query %q returned no samples", err, queryValue)
}

func prometheusInstantValue(ctx context.Context, baseURL string, query string) (float64, bool, error) {
	params := url.Values{}
	params.Set("query", query)
	endpoint := baseURL + "/api/v1/query?" + params.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, false, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, false, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, false, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return 0, false, fmt.Errorf("Prometheus query returned HTTP %d: %s", response.StatusCode, body)
	}

	var payload struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			Result []struct {
				Value []json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, false, err
	}
	if payload.Status != "success" {
		if strings.TrimSpace(payload.Error) == "" {
			return 0, false, fmt.Errorf("Prometheus query status %q", payload.Status)
		}
		return 0, false, fmt.Errorf("Prometheus query status %q: %s", payload.Status, payload.Error)
	}

	var maxValue float64
	sawValue := false
	for _, result := range payload.Data.Result {
		if len(result.Value) < 2 {
			continue
		}
		value, err := prometheusSampleValue(result.Value[1])
		if err != nil {
			return 0, false, err
		}
		if !sawValue || value > maxValue {
			maxValue = value
			sawValue = true
		}
	}
	return maxValue, sawValue, nil
}

func prometheusSampleValue(raw json.RawMessage) (float64, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return strconv.ParseFloat(text, 64)
	}
	var value float64
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, err
	}
	return value, nil
}

func waitGrafanaDashboard(args []string) error {
	flags := flag.NewFlagSet("wait-grafana-dashboard", flag.ExitOnError)
	baseURL := flags.String("base-url", "", "Grafana base URL")
	uid := flags.String("uid", "globacl-overview", "dashboard uid")
	timeout := flags.Duration("timeout", 120*time.Second, "wait timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	normalized, err := normalizeBaseURL(*baseURL)
	if err != nil {
		return err
	}
	dashboardUID := requireValue("uid", *uid)
	return waitUntil(*timeout, func(ctx context.Context) (bool, error) {
		if ok, err := grafanaHealthy(ctx, normalized); err != nil || !ok {
			return false, err
		}
		return grafanaDashboardExists(ctx, normalized, dashboardUID)
	})
}

func grafanaHealthy(ctx context.Context, baseURL string) (bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/health", nil)
	if err != nil {
		return false, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return false, nil
	}
	defer response.Body.Close()
	return response.StatusCode >= 200 && response.StatusCode < 300, nil
}

func grafanaDashboardExists(ctx context.Context, baseURL string, uid string) (bool, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		baseURL+"/api/dashboards/uid/"+url.PathEscape(uid),
		nil,
	)
	if err != nil {
		return false, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return false, nil
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(response.Body)
		return false, fmt.Errorf("Grafana dashboard lookup returned HTTP %d: %s", response.StatusCode, body)
	}
	var payload struct {
		Dashboard struct {
			UID string `json:"uid"`
		} `json:"dashboard"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return false, nil
	}
	return payload.Dashboard.UID == uid, nil
}

func newClient(baseURL string) (*globacl.Client, error) {
	normalized, err := normalizeBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	options := []globacl.ClientOption{}
	if token := strings.TrimSpace(os.Getenv("GLOBACL_BEARER_TOKEN")); token != "" {
		options = append(options, globacl.WithBearerToken(token))
	}
	return globacl.NewClient(normalized, options...)
}

func normalizeBaseURL(baseURL string) (string, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	baseURL = strings.TrimSuffix(baseURL, "/health")
	if baseURL == "" {
		return "", fmt.Errorf("--base-url is required")
	}
	return baseURL, nil
}

func deliveryPriorityValue(value string) (globacl.DeliveryPriorityValue, error) {
	switch value {
	case "p0":
		return globacl.DeliveryPriorityValueP0, nil
	case "p1":
		return globacl.DeliveryPriorityValueP1, nil
	case "p2":
		return globacl.DeliveryPriorityValueP2, nil
	default:
		return "", fmt.Errorf("invalid delivery priority %q", value)
	}
}

func waitUntil(timeout time.Duration, condition func(context.Context) (bool, error)) error {
	deadline := time.Now().Add(timeout)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ok, err := condition(ctx)
		cancel()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s", timeout)
		}
		time.Sleep(time.Second)
	}
}

func requireValue(name string, value string) string {
	if strings.TrimSpace(value) == "" {
		fatalf("--%s is required", name)
	}
	return value
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
