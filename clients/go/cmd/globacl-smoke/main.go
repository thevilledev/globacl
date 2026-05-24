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
	"strings"
	"time"

	"github.com/thevilledev/globacl/clients/go/globacl"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: globacl-smoke <wait-health|require-health-fields|deny|wait-demo-deny|wait-propagation>")
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
	case "wait-propagation":
		err = waitPropagation(os.Args[2:])
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
	return waitUntil(*timeout, func(ctx context.Context) (bool, error) {
		health, err := client.Health(ctx)
		if err != nil {
			return false, nil
		}
		return health.Status == globacl.HealthResponseStatusOk ||
			health.Status == globacl.HealthResponseStatusDegraded ||
			health.Status == globacl.HealthResponseStatusStale, nil
	})
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
	return waitUntil(*timeout, func(ctx context.Context) (bool, error) {
		health, err := client.Health(ctx)
		if err != nil {
			return false, nil
		}
		for _, field := range requiredFields {
			if _, ok := health.Get(strings.TrimSpace(field)); !ok {
				return false, nil
			}
		}
		return true, nil
	})
}

func deny(args []string) error {
	flags := flag.NewFlagSet("deny", flag.ExitOnError)
	baseURL := flags.String("base-url", "", "control base URL")
	opID := flags.String("op-id", "", "operation id")
	tenantID := flags.String("tenant-id", "", "tenant id")
	namespace := flags.String("namespace", "", "namespace")
	key := flags.String("key", "", "key")
	reasonCode := flags.String("reason-code", "smoke", "reason code")
	createdBy := flags.String("created-by", "smoke", "creator")
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
	fmt.Printf("committed shard_id=%d seq=%d duplicate=%v\n", outcome.ShardId, outcome.Seq, outcome.Duplicate)
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
