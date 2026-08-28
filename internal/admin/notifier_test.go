package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeOutboxStore mirrors the PostgreSQL lease semantics of ClaimOutboxEvents
// and RecordNotificationResult in memory so the worker lifecycle can be
// exercised without a database.
type fakeOutboxStore struct {
	mu          sync.Mutex
	events      []*OutboxEvent
	settlements []fakeSettlement
}

type fakeSettlement struct {
	eventID string
	success bool
	reason  string
}

func (store *fakeOutboxStore) add(event OutboxEvent) {
	store.mu.Lock()
	defer store.mu.Unlock()
	copied := event
	store.events = append(store.events, &copied)
}

func (store *fakeOutboxStore) ClaimOutboxEvents(_ context.Context, limit, maxAttempts int) ([]OutboxEvent, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var claimed []OutboxEvent
	for _, event := range store.events {
		if len(claimed) == limit {
			break
		}
		claimable := event.Status == OutboxPending ||
			(event.Status == OutboxFailed && event.Attempt < maxAttempts) ||
			(event.Status == OutboxClaimed && event.Attempt < maxAttempts)
		if !claimable {
			continue
		}
		event.Status = OutboxClaimed
		event.Attempt++
		claimed = append(claimed, *event)
	}
	return claimed, nil
}

func (store *fakeOutboxStore) RecordNotificationResult(_ context.Context, eventID string, success bool, reason string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, event := range store.events {
		if event.ID != eventID {
			continue
		}
		if event.Status != OutboxClaimed {
			return fmt.Errorf("outbox event is not in %q state", OutboxClaimed)
		}
		if success {
			event.Status = OutboxSent
		} else {
			event.Status = OutboxFailed
		}
		store.settlements = append(store.settlements, fakeSettlement{eventID: eventID, success: success, reason: reason})
		return nil
	}
	return errors.New("outbox event not found")
}

func (store *fakeOutboxStore) lastSettlement() fakeSettlement {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.settlements[len(store.settlements)-1]
}

func (store *fakeOutboxStore) statusOf(eventID string) string {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, event := range store.events {
		if event.ID == eventID {
			return event.Status
		}
	}
	return ""
}

func testOutboxEvent(id string, attempt int) OutboxEvent {
	payload, _ := json.Marshal(ActivationNoticePayload{
		RequestID:        "request-" + id,
		ContactChannel:   "email",
		ContactReference: "fisher@example.invalid",
		ActivatedAt:      time.Now().UTC(),
	})
	return OutboxEvent{
		ID:                  id,
		RequestID:           "request-" + id,
		Topic:               OutboxTopicPlatformOnboarding,
		EventType:           OutboxEventActivation,
		Classification:      OutboxClassificationConfidential,
		ProvenancePrincipal: "officer-subject-1",
		Payload:             payload,
		Status:              OutboxPending,
		Attempt:             attempt,
		CreatedAt:           time.Now().UTC(),
	}
}

func testNotifierConfig() NotifierConfig {
	return NotifierConfig{BatchSize: 10, PollInterval: time.Second, MaxAttempts: 8}
}

func newTestNotifier(store NotifierStore, channel NoticeChannel) *Notifier {
	notifier := NewNotifier(store, channel, testNotifierConfig(), nil)
	notifier.backoffBase = time.Millisecond
	return notifier
}

// TestNotifierWebhookDelivery proves the claim/deliver/record lifecycle:
// a pending event is claimed, POSTed as the platform envelope with the HMAC
// signature header, and settled sent.
func TestNotifierWebhookDelivery(t *testing.T) {
	var received webhookEnvelope
	var signature, eventHeader, deliveryHeader string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		signature = request.Header.Get("X-Blueeconomy-Signature-256")
		eventHeader = request.Header.Get("X-Blueeconomy-Event")
		deliveryHeader = request.Header.Get("X-Blueeconomy-Delivery")
		if err := json.Unmarshal(body, &received); err != nil {
			t.Errorf("webhook body is not the notice envelope: %v", err)
		}
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := NotifierConfig{
		Channel:           "webhook",
		BatchSize:         10,
		PollInterval:      time.Second,
		MaxAttempts:       8,
		WebhookHMACSecret: "test-hmac-secret",
	}
	config.WebhookURL = mustParseURL(t, server.URL)
	channel, err := config.BuildChannel()
	if err != nil {
		t.Fatalf("build webhook channel: %v", err)
	}
	store := &fakeOutboxStore{}
	store.add(testOutboxEvent("event-1", 0))
	sentBefore := notifierSentTotal.Value()
	newTestNotifier(store, channel).drain(context.Background())

	settlement := store.lastSettlement()
	if !settlement.success || settlement.eventID != "event-1" {
		t.Fatalf("expected successful settlement for event-1, got %+v", settlement)
	}
	if got := store.statusOf("event-1"); got != OutboxSent {
		t.Fatalf("expected event status sent, got %q", got)
	}
	if received.EventID != "event-1" || received.Topic != OutboxTopicPlatformOnboarding || received.EventType != OutboxEventActivation {
		t.Fatalf("webhook envelope lost the outbox identity: %+v", received)
	}
	var payload ActivationNoticePayload
	if err := json.Unmarshal(received.Payload, &payload); err != nil || payload.ContactReference != "fisher@example.invalid" {
		t.Fatalf("webhook payload lost the contact reference: %v %+v", err, payload)
	}
	if eventHeader != OutboxEventActivation || deliveryHeader != "event-1" {
		t.Fatalf("webhook routing headers missing: %q %q", eventHeader, deliveryHeader)
	}
	if !strings.HasPrefix(signature, "sha256=") || len(signature) != len("sha256=")+64 {
		t.Fatalf("HMAC signature header missing or malformed: %q", signature)
	}
	if notifierSentTotal.Value() != sentBefore+1 {
		t.Fatalf("sent metric did not increase")
	}
}

// TestNotifierWebhookPermanentFailure proves a 4xx webhook rejection settles
// the event failed immediately, with no retry and no silent drop.
func TestNotifierWebhookPermanentFailure(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls++
		writer.WriteHeader(http.StatusUnprocessableEntity)
	}))
	defer server.Close()
	config := NotifierConfig{Channel: "webhook", BatchSize: 10, PollInterval: time.Second, MaxAttempts: 8}
	config.WebhookURL = mustParseURL(t, server.URL)
	channel, _ := config.BuildChannel()
	store := &fakeOutboxStore{}
	store.add(testOutboxEvent("event-perm", 0))
	failedBefore := notifierFailedTotal.Value()
	notifier := newTestNotifier(store, channel)
	notifier.drain(context.Background())

	if calls != 1 {
		t.Fatalf("permanent failure must not be retried, webhook saw %d calls", calls)
	}
	settlement := store.lastSettlement()
	if settlement.success || !strings.Contains(settlement.reason, "HTTP 422") {
		t.Fatalf("expected permanent failed settlement, got %+v", settlement)
	}
	if got := store.statusOf("event-perm"); got != OutboxFailed {
		t.Fatalf("expected terminal failed status, got %q", got)
	}
	if notifierFailedTotal.Value() != failedBefore+1 {
		t.Fatalf("failed metric did not increase")
	}
}

// TestNotifierWebhookTransientRetry proves a 5xx failure is retried with
// backoff inside the lease and settles sent once delivery succeeds.
func TestNotifierWebhookTransientRetry(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls++
		if calls < 3 {
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	config := NotifierConfig{Channel: "webhook", BatchSize: 10, PollInterval: time.Second, MaxAttempts: 8}
	config.WebhookURL = mustParseURL(t, server.URL)
	channel, _ := config.BuildChannel()
	store := &fakeOutboxStore{}
	store.add(testOutboxEvent("event-retry", 0))
	retriedBefore := notifierRetriedTotal.Value()
	newTestNotifier(store, channel).drain(context.Background())

	if calls != 3 {
		t.Fatalf("expected 3 delivery attempts, got %d", calls)
	}
	if settlement := store.lastSettlement(); !settlement.success {
		t.Fatalf("transient failure must settle sent after recovery, got %+v", settlement)
	}
	if notifierRetriedTotal.Value() != retriedBefore+2 {
		t.Fatalf("retry metric did not count the two transient attempts")
	}
}

// TestNotifierMaxAttemptsTerminal proves an event on its last allowed attempt
// is settled failed (never dropped, never reclaimed past the budget) when
// delivery keeps failing transiently.
func TestNotifierMaxAttemptsTerminal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	config := NotifierConfig{Channel: "webhook", BatchSize: 10, PollInterval: time.Second, MaxAttempts: 8}
	config.WebhookURL = mustParseURL(t, server.URL)
	channel, _ := config.BuildChannel()
	store := &fakeOutboxStore{}
	event := testOutboxEvent("event-last", 7) // next claim is attempt 8 == max
	store.add(event)
	notifier := newTestNotifier(store, channel)
	notifier.drain(context.Background())

	settlement := store.lastSettlement()
	if settlement.success || !strings.Contains(settlement.reason, "attempts exhausted (8/8)") {
		t.Fatalf("expected terminal exhaustion settlement, got %+v", settlement)
	}
	// The terminal failed event must never be reclaimed: the claim filter
	// excludes failed events at or beyond the attempt budget.
	claimed, err := store.ClaimOutboxEvents(context.Background(), 10, 8)
	if err != nil || len(claimed) != 0 {
		t.Fatalf("terminal failed event was reclaimed: %v %v", claimed, err)
	}
}

// TestNotifierUndeliverablePayload proves a corrupt payload is failed
// permanently instead of crashing or being dropped.
func TestNotifierUndeliverablePayload(t *testing.T) {
	store := &fakeOutboxStore{}
	event := testOutboxEvent("event-corrupt", 0)
	event.Payload = json.RawMessage(`{"contact_channel":`)
	store.add(event)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls++
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	config := NotifierConfig{Channel: "webhook", BatchSize: 10, PollInterval: time.Second, MaxAttempts: 8}
	config.WebhookURL = mustParseURL(t, server.URL)
	channel, _ := config.BuildChannel()
	newTestNotifier(store, channel).drain(context.Background())

	if calls != 0 {
		t.Fatalf("corrupt payload must never hit the channel, saw %d calls", calls)
	}
	settlement := store.lastSettlement()
	if settlement.success || !strings.Contains(settlement.reason, "undeliverable") {
		t.Fatalf("expected permanent payload failure, got %+v", settlement)
	}
}

func mustParseURL(t *testing.T, raw string) (parsed *url.URL) {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse test URL: %v", err)
	}
	return parsed
}

// fakeSMTPServer is a minimal net/textproto SMTP harness for delivery tests.
type fakeSMTPServer struct {
	listener net.Listener
	mu       sync.Mutex
	rcptCode int
	rcptTo   []string
	messages []string
}

func newFakeSMTPServer(t *testing.T) *fakeSMTPServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for fake SMTP server: %v", err)
	}
	server := &fakeSMTPServer{listener: listener, rcptCode: 250}
	go server.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return server
}

func (server *fakeSMTPServer) serve() {
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			return
		}
		go server.handle(connection)
	}
}

func (server *fakeSMTPServer) handle(connection net.Conn) {
	defer func() { _ = connection.Close() }()
	protocol := textproto.NewConn(connection)
	defer protocol.Close()
	_ = protocol.PrintfLine("220 fake.invalid ESMTP")
	for {
		line, err := protocol.ReadLine()
		if err != nil {
			return
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			_ = protocol.PrintfLine("250-fake.invalid greets you")
			_ = protocol.PrintfLine("250 8BITMIME")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			_ = protocol.PrintfLine("250 2.1.0 Ok")
		case strings.HasPrefix(upper, "RCPT TO:"):
			server.mu.Lock()
			server.rcptTo = append(server.rcptTo, line)
			code := server.rcptCode
			server.mu.Unlock()
			switch code {
			case 550:
				_ = protocol.PrintfLine("550 5.1.1 mailbox unavailable")
			case 450:
				_ = protocol.PrintfLine("450 4.7.1 try again later")
			default:
				_ = protocol.PrintfLine("250 2.1.5 Ok")
			}
		case upper == "DATA":
			_ = protocol.PrintfLine("354 End data with <CR><LF>.<CR><LF>")
			body, err := io.ReadAll(protocol.DotReader())
			if err == nil {
				server.mu.Lock()
				server.messages = append(server.messages, string(body))
				server.mu.Unlock()
			}
			_ = protocol.PrintfLine("250 2.0.0 Ok: queued")
		case upper == "NOOP" || upper == "RSET":
			_ = protocol.PrintfLine("250 2.0.0 Ok")
		case upper == "QUIT":
			_ = protocol.PrintfLine("221 2.0.0 Bye")
			return
		default:
			_ = protocol.PrintfLine("502 5.5.2 command not recognized")
		}
	}
}

func (server *fakeSMTPServer) addr() (string, int) {
	address := server.listener.Addr().(*net.TCPAddr)
	return address.IP.String(), address.Port
}

func (server *fakeSMTPServer) rcptAttempts() int {
	server.mu.Lock()
	defer server.mu.Unlock()
	return len(server.rcptTo)
}

func (server *fakeSMTPServer) lastMessage() string {
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.messages) == 0 {
		return ""
	}
	return server.messages[len(server.messages)-1]
}

func smtpNotifierConfig(host string, port int) NotifierConfig {
	return NotifierConfig{
		Channel:      "smtp",
		BatchSize:    10,
		PollInterval: time.Second,
		MaxAttempts:  8,
		SMTPHost:     host,
		SMTPPort:     port,
		SMTPFrom:     "notifier@example.invalid",
		SMTPTLSMode:  "none",
	}
}

// TestNotifierSMTPDelivery proves the SMTP channel renders and delivers the
// activation notice with the enrollment reference, then settles sent.
func TestNotifierSMTPDelivery(t *testing.T) {
	server := newFakeSMTPServer(t)
	host, port := server.addr()
	channel, err := smtpNotifierConfig(host, port).BuildChannel()
	if err != nil {
		t.Fatalf("build smtp channel: %v", err)
	}
	store := &fakeOutboxStore{}
	event := testOutboxEvent("event-smtp", 0)
	store.add(event)
	newTestNotifier(store, channel).drain(context.Background())

	settlement := store.lastSettlement()
	if !settlement.success {
		t.Fatalf("smtp delivery should settle sent, got %+v", settlement)
	}
	message := server.lastMessage()
	if message == "" {
		t.Fatalf("fake SMTP server captured no message")
	}
	for _, fragment := range []string{
		"To: fisher@example.invalid",
		"Subject: Blue Economy platform access activated",
		"Onboarding reference: " + event.RequestID,
	} {
		if !strings.Contains(message, fragment) {
			t.Fatalf("activation notice is missing %q:\n%s", fragment, message)
		}
	}
}

// TestNotifierSMTPRecipientRejection proves a 5xx RCPT rejection is a
// permanent failure: settled failed immediately without retry.
func TestNotifierSMTPRecipientRejection(t *testing.T) {
	server := newFakeSMTPServer(t)
	server.rcptCode = 550
	host, port := server.addr()
	channel, _ := smtpNotifierConfig(host, port).BuildChannel()
	store := &fakeOutboxStore{}
	store.add(testOutboxEvent("event-550", 0))
	newTestNotifier(store, channel).drain(context.Background())

	if attempts := server.rcptAttempts(); attempts != 1 {
		t.Fatalf("permanent recipient rejection must not be retried, saw %d RCPT attempts", attempts)
	}
	settlement := store.lastSettlement()
	if settlement.success || !strings.Contains(settlement.reason, "550") {
		t.Fatalf("expected permanent 550 settlement, got %+v", settlement)
	}
	if got := store.statusOf("event-550"); got != OutboxFailed {
		t.Fatalf("expected terminal failed status, got %q", got)
	}
}

// TestNotifierSMTPTransientRejection proves a 4xx RCPT reply is transient:
// retried in-lease and then settled failed-but-reclaimable (attempts remain),
// never sent and never dropped.
func TestNotifierSMTPTransientRejection(t *testing.T) {
	server := newFakeSMTPServer(t)
	server.rcptCode = 450
	host, port := server.addr()
	channel, _ := smtpNotifierConfig(host, port).BuildChannel()
	store := &fakeOutboxStore{}
	store.add(testOutboxEvent("event-450", 0))
	notifier := newTestNotifier(store, channel)
	notifier.drain(context.Background())

	if attempts := server.rcptAttempts(); attempts != 1+notifier.inlineRetries {
		t.Fatalf("expected initial attempt plus %d inline retries, saw %d", notifier.inlineRetries, attempts)
	}
	settlement := store.lastSettlement()
	if settlement.success || !strings.Contains(settlement.reason, "transient") {
		t.Fatalf("expected reclaimable transient settlement, got %+v", settlement)
	}
	// Attempts remain, so the next claim re-leases the event for retry.
	claimed, err := store.ClaimOutboxEvents(context.Background(), 10, 8)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("transient failed event must stay claimable: %v %v", claimed, err)
	}
}

// TestNotifierSMTPUndeliverableReference proves a non-e-mail contact
// reference (for example an SMS number) is a permanent failure on the SMTP
// channel instead of a malformed submission to the server.
func TestNotifierSMTPUndeliverableReference(t *testing.T) {
	server := newFakeSMTPServer(t)
	host, port := server.addr()
	channel, _ := smtpNotifierConfig(host, port).BuildChannel()
	store := &fakeOutboxStore{}
	event := testOutboxEvent("event-sms-ref", 0)
	payload, _ := json.Marshal(ActivationNoticePayload{
		RequestID:        event.RequestID,
		ContactChannel:   "sms",
		ContactReference: "+2348012345678",
		ActivatedAt:      time.Now().UTC(),
	})
	event.Payload = payload
	store.add(event)
	newTestNotifier(store, channel).drain(context.Background())

	if attempts := server.rcptAttempts(); attempts != 0 {
		t.Fatalf("undeliverable reference must never reach the server, saw %d RCPT attempts", attempts)
	}
	settlement := store.lastSettlement()
	if settlement.success || !strings.Contains(settlement.reason, "not a deliverable e-mail address") {
		t.Fatalf("expected permanent reference failure, got %+v", settlement)
	}
}

// TestLoadNotifierConfigFailClosed proves missing or invalid configuration
// is a startup error and that sane defaults are applied.
func TestLoadNotifierConfigFailClosed(t *testing.T) {
	t.Setenv("ADMIN_NOTIFIER_POSTGRES_DSN", "")
	t.Setenv("ADMIN_SERVICE_POSTGRES_DSN", "")
	t.Setenv("ADMIN_NOTIFIER_CHANNEL", "")
	t.Setenv("ADMIN_NOTIFIER_BATCH_SIZE", "")
	t.Setenv("ADMIN_NOTIFIER_MAX_ATTEMPTS", "")
	t.Setenv("ADMIN_NOTIFIER_POLL_INTERVAL", "")
	t.Setenv("ADMIN_NOTIFIER_METRICS_ADDRESS", "")
	t.Setenv("ADMIN_NOTIFIER_SMTP_HOST", "")
	t.Setenv("ADMIN_NOTIFIER_SMTP_PORT", "")
	t.Setenv("ADMIN_NOTIFIER_SMTP_USERNAME", "")
	t.Setenv("ADMIN_NOTIFIER_SMTP_PASSWORD", "")
	t.Setenv("ADMIN_NOTIFIER_SMTP_FROM", "")
	t.Setenv("ADMIN_NOTIFIER_SMTP_TLS_MODE", "")
	t.Setenv("ADMIN_NOTIFIER_WEBHOOK_URL", "")
	t.Setenv("ADMIN_NOTIFIER_WEBHOOK_HMAC_SECRET", "")

	if _, err := LoadNotifierConfig(); err == nil || !strings.Contains(err.Error(), "POSTGRES_DSN") {
		t.Fatalf("missing DSN must be a startup error, got %v", err)
	}
	t.Setenv("ADMIN_SERVICE_POSTGRES_DSN", "postgres://example.invalid/admin")
	if _, err := LoadNotifierConfig(); err == nil || !strings.Contains(err.Error(), "ADMIN_NOTIFIER_CHANNEL") {
		t.Fatalf("missing channel must be a startup error, got %v", err)
	}
	t.Setenv("ADMIN_NOTIFIER_CHANNEL", "smtp")
	if _, err := LoadNotifierConfig(); err == nil || !strings.Contains(err.Error(), "SMTP_HOST") {
		t.Fatalf("missing SMTP host must be a startup error, got %v", err)
	}
	t.Setenv("ADMIN_NOTIFIER_SMTP_HOST", "smtp.example.invalid")
	if _, err := LoadNotifierConfig(); err == nil || !strings.Contains(err.Error(), "SMTP_FROM") {
		t.Fatalf("missing SMTP sender must be a startup error, got %v", err)
	}
	t.Setenv("ADMIN_NOTIFIER_SMTP_FROM", "notifier@example.invalid")
	t.Setenv("ADMIN_NOTIFIER_SMTP_USERNAME", "mailer")
	if _, err := LoadNotifierConfig(); err == nil || !strings.Contains(err.Error(), "set together") {
		t.Fatalf("half-configured SMTP auth must be a startup error, got %v", err)
	}
	t.Setenv("ADMIN_NOTIFIER_SMTP_USERNAME", "")
	config, err := LoadNotifierConfig()
	if err != nil {
		t.Fatalf("valid smtp configuration was rejected: %v", err)
	}
	if config.SMTPTLSMode != "starttls" || config.SMTPPort != 587 {
		t.Fatalf("smtp defaults wrong: mode=%q port=%d", config.SMTPTLSMode, config.SMTPPort)
	}
	if config.BatchSize != 25 || config.MaxAttempts != 8 || config.PollInterval != 5*time.Second {
		t.Fatalf("worker defaults wrong: %+v", config)
	}

	t.Setenv("ADMIN_NOTIFIER_CHANNEL", "webhook")
	if _, err := LoadNotifierConfig(); err == nil || !strings.Contains(err.Error(), "WEBHOOK_URL") {
		t.Fatalf("missing webhook URL must be a startup error, got %v", err)
	}
	t.Setenv("ADMIN_NOTIFIER_WEBHOOK_URL", "https://user:secret@gateway.example.invalid/hook")
	if _, err := LoadNotifierConfig(); err == nil {
		t.Fatalf("webhook URL with credentials must be rejected")
	}
	t.Setenv("ADMIN_NOTIFIER_WEBHOOK_URL", "https://gateway.example.invalid/hook")
	if _, err := LoadNotifierConfig(); err != nil {
		t.Fatalf("valid webhook configuration was rejected: %v", err)
	}
	t.Setenv("ADMIN_NOTIFIER_MAX_ATTEMPTS", "0")
	if _, err := LoadNotifierConfig(); err == nil {
		t.Fatalf("zero max attempts must be a startup error")
	}
}

// TestOutboxLeaseExpiryReclaim exercises the real PostgreSQL lease: an event
// whose lease expired (crashed worker) is re-claimed, settled, and mirrored
// onto the request; a terminally failed event is never reclaimed. Gated on a
// migrated database per the integration convention.
func TestOutboxLeaseExpiryReclaim(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ADMIN_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("ADMIN_TEST_POSTGRES_DSN is not set; skipping database-gated outbox lease test")
	}
	ctx := context.Background()
	store, err := NewStore(ctx, dsn)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer store.Close()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	insertRequest := func() string {
		var requestID string
		const query = `
		INSERT INTO onboarding_requests (organization_id, email, first_name, last_name, requested_roles, requester_subject, status)
		VALUES ('notifier-test', $1, 'Test', 'User', '{platform-admin}', 'notifier-test-officer', 'active')
		RETURNING id::text`
		if err := store.pool.QueryRow(ctx, query, "notifier-"+suffix+"-"+requestIDSeed()+"@example.invalid").Scan(&requestID); err != nil {
			t.Fatalf("insert test request: %v", err)
		}
		return requestID
	}
	insertEvent := func(requestID string) string {
		var eventID string
		payload := fmt.Sprintf(`{"request_id":%q,"contact_channel":"email","contact_reference":"fisher@example.invalid","activated_at":%q}`,
			requestID, time.Now().UTC().Format(time.RFC3339Nano))
		const query = `
		INSERT INTO onboarding_outbox_events (request_id, topic, event_type, classification, provenance_principal, payload)
		VALUES ($1, 'platform.onboarding.v1', 'onboarding.activated.v1', 'CONFIDENTIAL', 'notifier-test-officer', $2)
		RETURNING id::text`
		if err := store.pool.QueryRow(ctx, query, requestID, payload).Scan(&eventID); err != nil {
			t.Fatalf("insert test outbox event: %v", err)
		}
		return eventID
	}

	// Pending event is claimed once, settled sent, and mirrored.
	firstRequest := insertRequest()
	firstEvent := insertEvent(firstRequest)
	claimed, err := store.ClaimOutboxEvents(ctx, 10, 8)
	if err != nil || len(claimed) != 1 || claimed[0].ID != firstEvent || claimed[0].Attempt != 1 {
		t.Fatalf("first claim wrong: %+v %v", claimed, err)
	}
	if err := store.RecordNotificationResult(ctx, firstEvent, true, ""); err != nil {
		t.Fatalf("record sent result: %v", err)
	}
	var mirror string
	if err := store.pool.QueryRow(ctx, `SELECT notification_status FROM onboarding_requests WHERE id = $1`, firstRequest).Scan(&mirror); err != nil || mirror != NotificationSent {
		t.Fatalf("notification mirror wrong: %q %v", mirror, err)
	}

	// A crashed worker's expired lease is re-claimed with a bumped attempt.
	secondRequest := insertRequest()
	secondEvent := insertEvent(secondRequest)
	if _, err := store.pool.Exec(ctx, `UPDATE onboarding_outbox_events SET status = 'claimed', attempt = 2, lease_until = now() - interval '1 minute' WHERE id = $1`, secondEvent); err != nil {
		t.Fatalf("force expired lease: %v", err)
	}
	claimed, err = store.ClaimOutboxEvents(ctx, 10, 8)
	if err != nil || len(claimed) != 1 || claimed[0].ID != secondEvent || claimed[0].Attempt != 3 {
		t.Fatalf("expired lease was not re-claimed: %+v %v", claimed, err)
	}
	if err := store.RecordNotificationResult(ctx, secondEvent, false, "transient failure"); err != nil {
		t.Fatalf("record failed result: %v", err)
	}

	// Once the attempt budget is exhausted the terminal failed event stays
	// claimable-by-nobody: it is never reclaimed and never silently dropped.
	if _, err := store.pool.Exec(ctx, `UPDATE onboarding_outbox_events SET attempt = 8 WHERE id = $1`, secondEvent); err != nil {
		t.Fatalf("exhaust attempts: %v", err)
	}
	claimed, err = store.ClaimOutboxEvents(ctx, 10, 8)
	if err != nil || len(claimed) != 0 {
		t.Fatalf("terminally failed event was reclaimed: %+v %v", claimed, err)
	}
}

var requestIDCounter int

func requestIDSeed() string {
	requestIDCounter++
	return fmt.Sprintf("%d", requestIDCounter)
}
