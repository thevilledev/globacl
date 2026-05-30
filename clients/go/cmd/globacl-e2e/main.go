package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thevilledev/globacl/clients/go/globacl"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: globacl-e2e <wait-health|require-health-fields|deny|seed-denies|load-demo|wait-demo-deny|wait-check-deny|wait-propagation|wait-prometheus-query|wait-grafana-dashboard>")
	}

	var err error
	switch os.Args[1] {
	case "wait-health":
		err = waitHealth(os.Args[2:])
	case "require-health-fields":
		err = requireHealthFields(os.Args[2:])
	case "deny":
		err = deny(os.Args[2:])
	case "seed-denies":
		err = seedDenies(os.Args[2:])
	case "load-demo":
		err = loadDemo(os.Args[2:])
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

func seedDenies(args []string) error {
	flags := flag.NewFlagSet("seed-denies", flag.ExitOnError)
	baseURL := flags.String("base-url", "", "control base URL")
	count := flags.Int64("count", 0, "number of deny mutations to seed")
	keyspace := flags.Int64("keyspace", 100_000_000, "virtual user keyspace size")
	startIndex := flags.Int64("start-index", 0, "first virtual user index to seed")
	concurrency := flags.Int("concurrency", 32, "concurrent writers")
	tenantID := flags.String("tenant-id", "tenant-a", "tenant id")
	namespace := flags.String("namespace", "user", "namespace")
	opPrefix := flags.String("op-prefix", "scale-seed", "operation id prefix")
	reasonCode := flags.String("reason-code", "scale_seed", "reason code")
	createdBy := flags.String("created-by", "scale-e2e", "creator")
	deliveryPriority := flags.String("delivery-priority", "p1", "delivery priority")
	requestTimeout := flags.Duration("request-timeout", 15*time.Second, "per-request timeout")
	retries := flags.Int("retries", 5, "retries for transient write errors")
	retryDelay := flags.Duration("retry-delay", 250*time.Millisecond, "initial retry delay")
	progressEvery := flags.Duration("progress-every", 10*time.Second, "progress interval; 0 disables progress")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *count <= 0 {
		return fmt.Errorf("--count must be greater than zero")
	}
	if *keyspace <= 0 {
		return fmt.Errorf("--keyspace must be greater than zero")
	}
	if *count > *keyspace {
		return fmt.Errorf("--count (%d) must be less than or equal to --keyspace (%d)", *count, *keyspace)
	}
	if *startIndex < 0 || *startIndex+*count > *keyspace {
		return fmt.Errorf("--start-index plus --count must fit inside --keyspace")
	}
	if *concurrency <= 0 {
		return fmt.Errorf("--concurrency must be greater than zero")
	}
	if *retries < 0 {
		return fmt.Errorf("--retries must be greater than or equal to zero")
	}
	if *retryDelay < 0 {
		return fmt.Errorf("--retry-delay must be greater than or equal to zero")
	}
	tenant, err := requiredFlag("tenant-id", *tenantID)
	if err != nil {
		return err
	}
	ns, err := requiredFlag("namespace", *namespace)
	if err != nil {
		return err
	}
	prefix, err := requiredFlag("op-prefix", *opPrefix)
	if err != nil {
		return err
	}
	priority, err := deliveryPriorityValue(*deliveryPriority)
	if err != nil {
		return err
	}
	client, err := newClient(*baseURL)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := time.Now()
	jobs := make(chan int64, *concurrency*2)
	firstErr := make(chan error, 1)
	var stats seedStats
	var wg sync.WaitGroup

	reportDone := startSeedProgress(ctx, &stats, *count, started, *progressEvery)
	for worker := 0; worker < *concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				stats.attempted.Add(1)
				key := scaleUserKey(index, *keyspace)
				request := globacl.DenyMutationRequest{
					OpId:             fmt.Sprintf("%s-%d", prefix, index),
					TenantId:         tenant,
					Namespace:        ns,
					Key:              key,
					Action:           globacl.ActionDeny,
					ReasonCode:       reasonCode,
					CreatedBy:        createdBy,
					DeliveryPriority: &priority,
				}
				outcome, attempts, err := denyWithRetries(
					ctx,
					client,
					request,
					*requestTimeout,
					*retries,
					*retryDelay,
				)
				if attempts > 1 {
					stats.retries.Add(int64(attempts - 1))
				}
				if err != nil {
					stats.failed.Add(1)
					select {
					case firstErr <- fmt.Errorf("seed deny %s: %w", key, err):
						cancel()
					default:
					}
					continue
				}
				if outcome.Duplicate {
					stats.duplicates.Add(1)
				} else {
					stats.committed.Add(1)
				}
			}
		}()
	}

produceJobs:
	for offset := int64(0); offset < *count; offset++ {
		index := *startIndex + offset
		select {
		case <-ctx.Done():
			break produceJobs
		case jobs <- index:
		}
	}
	close(jobs)
	wg.Wait()
	cancel()
	if reportDone != nil {
		<-reportDone
	}

	select {
	case err := <-firstErr:
		return err
	default:
	}

	elapsed := time.Since(started)
	return printJSON(map[string]any{
		"status":      "seeded",
		"count":       *count,
		"attempted":   stats.attempted.Load(),
		"committed":   stats.committed.Load(),
		"duplicates":  stats.duplicates.Load(),
		"failed":      stats.failed.Load(),
		"retries":     stats.retries.Load(),
		"elapsed_ms":  elapsed.Milliseconds(),
		"mutations_s": ratePerSecond(stats.committed.Load()+stats.duplicates.Load(), elapsed),
	})
}

func loadDemo(args []string) error {
	flags := flag.NewFlagSet("load-demo", flag.ExitOnError)
	baseURLs := flags.String("base-url", "", "demo app base URL; comma-separated URLs are accepted")
	duration := flags.Duration("duration", time.Minute, "load duration")
	workers := flags.Int("workers", 16, "concurrent lookup workers")
	keyspace := flags.Int64("keyspace", 100_000_000, "virtual user keyspace size")
	deniedCount := flags.Int64("denied-count", 0, "number of seeded denied keys from the start of the keyspace")
	denyRatio := flags.Float64("deny-ratio", 0.001, "fraction of lookups that should hit seeded denied keys")
	tenantID := flags.String("tenant-id", "tenant-a", "tenant id")
	namespace := flags.String("namespace", "user", "namespace")
	requestTimeout := flags.Duration("request-timeout", 5*time.Second, "per-request timeout")
	retries := flags.Int("retries", 2, "retries for transient lookup transport errors")
	progressEvery := flags.Duration("progress-every", 10*time.Second, "progress interval; 0 disables progress")
	maxErrorRate := flags.Float64("max-error-rate", 0, "maximum allowed error/unexpected-decision rate")
	assertDecisions := flags.Bool("assert-decisions", true, "verify seeded keys deny and unseeded keys allow")
	if err := flags.Parse(args); err != nil {
		return err
	}
	urls, err := splitBaseURLs(*baseURLs)
	if err != nil {
		return err
	}
	if *duration <= 0 {
		return fmt.Errorf("--duration must be greater than zero")
	}
	if *workers <= 0 {
		return fmt.Errorf("--workers must be greater than zero")
	}
	if *keyspace <= 0 {
		return fmt.Errorf("--keyspace must be greater than zero")
	}
	if *deniedCount < 0 || *deniedCount > *keyspace {
		return fmt.Errorf("--denied-count must be between zero and --keyspace")
	}
	if *denyRatio < 0 || *denyRatio > 1 {
		return fmt.Errorf("--deny-ratio must be between 0 and 1")
	}
	if *maxErrorRate < 0 || *maxErrorRate > 1 {
		return fmt.Errorf("--max-error-rate must be between 0 and 1")
	}
	if *retries < 0 {
		return fmt.Errorf("--retries must be greater than or equal to zero")
	}
	if *assertDecisions && *denyRatio > 0 && *deniedCount == 0 {
		return fmt.Errorf("--denied-count must be greater than zero when --assert-decisions and --deny-ratio are set")
	}
	if *assertDecisions && *denyRatio < 1 && *deniedCount == *keyspace {
		return fmt.Errorf("--denied-count must be smaller than --keyspace when allowing negative lookups")
	}
	tenant, err := requiredFlag("tenant-id", *tenantID)
	if err != nil {
		return err
	}
	ns, err := requiredFlag("namespace", *namespace)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	httpClient := &http.Client{Timeout: *requestTimeout}
	started := time.Now()
	var stats loadStats
	var sequence atomic.Int64
	var lastError atomic.Value
	lastError.Store("")
	var wg sync.WaitGroup

	reportDone := startLoadProgress(ctx, &stats, started, *progressEvery)
	for worker := 0; worker < *workers; worker++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				seq := sequence.Add(1) - 1
				key, expectDeny := loadKey(seq, *keyspace, *deniedCount, *denyRatio)
				baseURL := urls[int(seq%int64(len(urls)))]
				statusCode, access, attempts, err := demoAccessWithRetries(
					httpClient,
					baseURL,
					tenant,
					ns,
					key,
					*requestTimeout,
					*retries,
				)
				stats.requests.Add(1)
				if attempts > 1 {
					stats.retries.Add(int64(attempts - 1))
				}
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					stats.errors.Add(1)
					lastError.Store(err.Error())
					continue
				}
				switch {
				case statusCode == http.StatusForbidden && access == "denied":
					stats.denied.Add(1)
					if *assertDecisions && !expectDeny {
						stats.unexpected.Add(1)
					}
				case statusCode >= 200 && statusCode < 300 && access == "allowed":
					stats.allowed.Add(1)
					if *assertDecisions && expectDeny {
						stats.unexpected.Add(1)
					}
				default:
					stats.unexpected.Add(1)
					lastError.Store(fmt.Sprintf("unexpected access=%q status=%d key=%s", access, statusCode, key))
				}
			}
		}(worker)
	}
	wg.Wait()
	if reportDone != nil {
		<-reportDone
	}

	elapsed := time.Since(started)
	requests := stats.requests.Load()
	if requests == 0 {
		return fmt.Errorf("load-demo completed without any requests")
	}
	bad := stats.errors.Load() + stats.unexpected.Load()
	errorRate := ratioFloat(bad, requests)
	if errorRate > *maxErrorRate {
		lastErrorText, _ := lastError.Load().(string)
		return fmt.Errorf(
			"load-demo error rate %.8f exceeded %.8f (errors=%d unexpected=%d requests=%d retries=%d last_error=%q)",
			errorRate,
			*maxErrorRate,
			stats.errors.Load(),
			stats.unexpected.Load(),
			requests,
			stats.retries.Load(),
			lastErrorText,
		)
	}
	lastErrorText, _ := lastError.Load().(string)

	return printJSON(map[string]any{
		"status":           "loaded",
		"duration_ms":      elapsed.Milliseconds(),
		"workers":          *workers,
		"requests":         requests,
		"allowed":          stats.allowed.Load(),
		"denied":           stats.denied.Load(),
		"errors":           stats.errors.Load(),
		"retries":          stats.retries.Load(),
		"unexpected":       stats.unexpected.Load(),
		"error_rate":       errorRate,
		"last_error":       lastErrorText,
		"requests_second":  ratePerSecond(requests, elapsed),
		"demo_base_url_ct": len(urls),
	})
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

type seedStats struct {
	attempted  atomic.Int64
	committed  atomic.Int64
	duplicates atomic.Int64
	failed     atomic.Int64
	retries    atomic.Int64
}

type loadStats struct {
	requests   atomic.Int64
	allowed    atomic.Int64
	denied     atomic.Int64
	errors     atomic.Int64
	retries    atomic.Int64
	unexpected atomic.Int64
}

func startSeedProgress(
	ctx context.Context,
	stats *seedStats,
	total int64,
	started time.Time,
	interval time.Duration,
) <-chan struct{} {
	if interval <= 0 {
		return nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				printSeedProgress(stats, total, started)
				return
			case <-ticker.C:
				printSeedProgress(stats, total, started)
			}
		}
	}()
	return done
}

func printSeedProgress(stats *seedStats, total int64, started time.Time) {
	attempted := stats.attempted.Load()
	done := stats.committed.Load() + stats.duplicates.Load()
	fmt.Fprintf(
		os.Stderr,
		"seed-denies progress attempted=%d done=%d/%d failed=%d retries=%d rate=%.1f/s\n",
		attempted,
		done,
		total,
		stats.failed.Load(),
		stats.retries.Load(),
		ratePerSecond(done, time.Since(started)),
	)
}

func startLoadProgress(
	ctx context.Context,
	stats *loadStats,
	started time.Time,
	interval time.Duration,
) <-chan struct{} {
	if interval <= 0 {
		return nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				printLoadProgress(stats, started)
				return
			case <-ticker.C:
				printLoadProgress(stats, started)
			}
		}
	}()
	return done
}

func printLoadProgress(stats *loadStats, started time.Time) {
	requests := stats.requests.Load()
	fmt.Fprintf(
		os.Stderr,
		"load-demo progress requests=%d allowed=%d denied=%d errors=%d retries=%d unexpected=%d rate=%.1f/s\n",
		requests,
		stats.allowed.Load(),
		stats.denied.Load(),
		stats.errors.Load(),
		stats.retries.Load(),
		stats.unexpected.Load(),
		ratePerSecond(requests, time.Since(started)),
	)
}

func denyWithRetries(
	ctx context.Context,
	client *globacl.Client,
	request globacl.DenyMutationRequest,
	requestTimeout time.Duration,
	retries int,
	retryDelay time.Duration,
) (*globacl.CommitOutcomeResponse, int, error) {
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		requestCtx, requestCancel := context.WithTimeout(ctx, requestTimeout)
		outcome, err := client.Deny(requestCtx, request)
		requestCancel()
		if err == nil {
			return outcome, attempt + 1, nil
		}
		lastErr = err
		if !retryableWriteError(err) || attempt == retries {
			return nil, attempt + 1, err
		}
		if err := sleepWithContext(ctx, retryDelayForAttempt(retryDelay, attempt)); err != nil {
			return nil, attempt + 1, lastErr
		}
	}
	return nil, retries + 1, lastErr
}

func retryableWriteError(err error) bool {
	var apiErr globacl.APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusTooManyRequests ||
			apiErr.StatusCode == http.StatusBadGateway ||
			apiErr.StatusCode == http.StatusServiceUnavailable ||
			apiErr.StatusCode == http.StatusGatewayTimeout ||
			apiErr.StatusCode >= http.StatusInternalServerError
	}
	return true
}

func retryDelayForAttempt(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		return 0
	}
	if attempt > 5 {
		attempt = 5
	}
	return base * time.Duration(1<<attempt)
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func splitBaseURLs(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	urls := make([]string, 0, len(parts))
	for _, part := range parts {
		baseURL, err := normalizeBaseURL(part)
		if err != nil {
			return nil, err
		}
		urls = append(urls, baseURL)
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("--base-url is required")
	}
	return urls, nil
}

func scaleUserKey(index int64, keyspace int64) string {
	normalized := index % keyspace
	if normalized < 0 {
		normalized += keyspace
	}
	return fmt.Sprintf("user-%d", normalized)
}

func loadKey(sequence int64, keyspace int64, deniedCount int64, denyRatio float64) (string, bool) {
	if shouldUseDeniedKey(sequence, deniedCount, denyRatio) {
		return scaleUserKey(sequence%deniedCount, keyspace), true
	}
	allowCount := keyspace - deniedCount
	if allowCount <= 0 {
		return scaleUserKey(sequence%keyspace, keyspace), true
	}
	return scaleUserKey(deniedCount+(sequence%allowCount), keyspace), false
}

func shouldUseDeniedKey(sequence int64, deniedCount int64, denyRatio float64) bool {
	if deniedCount <= 0 || denyRatio <= 0 {
		return false
	}
	if denyRatio >= 1 {
		return true
	}
	const scale = uint64(1_000_000)
	threshold := uint64(denyRatio*float64(scale) + 0.5)
	if threshold == 0 {
		threshold = 1
	}
	return mix64(uint64(sequence))%scale < threshold
}

func mix64(value uint64) uint64 {
	value += 0x9e3779b97f4a7c15
	value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9
	value = (value ^ (value >> 27)) * 0x94d049bb133111eb
	return value ^ (value >> 31)
}

func demoAccess(
	ctx context.Context,
	httpClient *http.Client,
	baseURL string,
	tenantID string,
	namespace string,
	key string,
) (int, string, error) {
	params := url.Values{}
	params.Set("tenant_id", tenantID)
	params.Set("namespace", namespace)
	params.Set("key", key)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/access?"+params.Encode(), nil)
	if err != nil {
		return 0, "", err
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return response.StatusCode, "", err
	}
	var payload struct {
		Access string `json:"access"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return response.StatusCode, "", err
	}
	return response.StatusCode, payload.Access, nil
}

func demoAccessWithRetries(
	httpClient *http.Client,
	baseURL string,
	tenantID string,
	namespace string,
	key string,
	requestTimeout time.Duration,
	retries int,
) (int, string, int, error) {
	var lastStatusCode int
	var lastAccess string
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		statusCode, access, err := demoAccess(ctx, httpClient, baseURL, tenantID, namespace, key)
		cancel()
		lastStatusCode = statusCode
		lastAccess = access
		if err == nil {
			return statusCode, access, attempt + 1, nil
		}
		lastErr = err
	}
	return lastStatusCode, lastAccess, retries + 1, lastErr
}

func printJSON(value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

func ratioFloat(numerator int64, denominator int64) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func ratePerSecond(count int64, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(count) / elapsed.Seconds()
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

func requiredFlag(name string, value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("--%s is required", name)
	}
	return value, nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
