package admin

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// NotifierConfig is the fail-closed environment contract of the
// admin-notifier worker. Any missing or invalid required value is a startup
// error; the worker never falls back to a placeholder channel or credential.
type NotifierConfig struct {
	PostgresDSN       string
	Channel           string
	BatchSize         int
	PollInterval      time.Duration
	MaxAttempts       int
	MetricsAddress    string
	SMTPHost          string
	SMTPPort          int
	SMTPUsername      string
	SMTPPassword      string
	SMTPFrom          string
	SMTPTLSMode       string
	WebhookURL        *url.URL
	WebhookHMACSecret string
}

// LoadNotifierConfig reads and validates the admin-notifier environment.
func LoadNotifierConfig() (NotifierConfig, error) {
	config := NotifierConfig{
		PostgresDSN:       firstEnv("ADMIN_NOTIFIER_POSTGRES_DSN", "ADMIN_SERVICE_POSTGRES_DSN"),
		Channel:           strings.ToLower(strings.TrimSpace(os.Getenv("ADMIN_NOTIFIER_CHANNEL"))),
		BatchSize:         25,
		PollInterval:      5 * time.Second,
		MaxAttempts:       8,
		MetricsAddress:    strings.TrimSpace(os.Getenv("ADMIN_NOTIFIER_METRICS_ADDRESS")),
		SMTPHost:          strings.TrimSpace(os.Getenv("ADMIN_NOTIFIER_SMTP_HOST")),
		SMTPUsername:      strings.TrimSpace(os.Getenv("ADMIN_NOTIFIER_SMTP_USERNAME")),
		SMTPPassword:      os.Getenv("ADMIN_NOTIFIER_SMTP_PASSWORD"),
		SMTPFrom:          strings.TrimSpace(os.Getenv("ADMIN_NOTIFIER_SMTP_FROM")),
		SMTPTLSMode:       strings.ToLower(strings.TrimSpace(os.Getenv("ADMIN_NOTIFIER_SMTP_TLS_MODE"))),
		WebhookHMACSecret: os.Getenv("ADMIN_NOTIFIER_WEBHOOK_HMAC_SECRET"),
	}
	if config.PostgresDSN == "" {
		return NotifierConfig{}, errors.New("ADMIN_NOTIFIER_POSTGRES_DSN (or ADMIN_SERVICE_POSTGRES_DSN) is required")
	}
	if config.Channel != "smtp" && config.Channel != "webhook" {
		return NotifierConfig{}, errors.New("ADMIN_NOTIFIER_CHANNEL is required and must be smtp or webhook")
	}
	var err error
	if config.BatchSize, err = intEnv("ADMIN_NOTIFIER_BATCH_SIZE", config.BatchSize, 1, 500); err != nil {
		return NotifierConfig{}, err
	}
	if config.MaxAttempts, err = intEnv("ADMIN_NOTIFIER_MAX_ATTEMPTS", config.MaxAttempts, 1, 100); err != nil {
		return NotifierConfig{}, err
	}
	if value := strings.TrimSpace(os.Getenv("ADMIN_NOTIFIER_POLL_INTERVAL")); value != "" {
		if config.PollInterval, err = time.ParseDuration(value); err != nil || config.PollInterval < time.Second || config.PollInterval > 5*time.Minute {
			return NotifierConfig{}, errors.New("ADMIN_NOTIFIER_POLL_INTERVAL must be a duration between 1s and 5m")
		}
	}
	if config.MetricsAddress != "" {
		if _, err := net.ResolveTCPAddr("tcp", config.MetricsAddress); err != nil {
			return NotifierConfig{}, fmt.Errorf("ADMIN_NOTIFIER_METRICS_ADDRESS is invalid: %w", err)
		}
	}
	switch config.Channel {
	case "smtp":
		if config.SMTPHost == "" {
			return NotifierConfig{}, errors.New("ADMIN_NOTIFIER_SMTP_HOST is required for the smtp channel")
		}
		if config.SMTPTLSMode == "" {
			config.SMTPTLSMode = "starttls"
		}
		if config.SMTPTLSMode != "starttls" && config.SMTPTLSMode != "tls" && config.SMTPTLSMode != "none" {
			return NotifierConfig{}, errors.New("ADMIN_NOTIFIER_SMTP_TLS_MODE must be starttls, tls or none")
		}
		defaultPort := 587
		if config.SMTPTLSMode == "tls" {
			defaultPort = 465
		} else if config.SMTPTLSMode == "none" {
			defaultPort = 25
		}
		if config.SMTPPort, err = intEnv("ADMIN_NOTIFIER_SMTP_PORT", defaultPort, 1, 65535); err != nil {
			return NotifierConfig{}, err
		}
		if (config.SMTPUsername == "") != (config.SMTPPassword == "") {
			return NotifierConfig{}, errors.New("ADMIN_NOTIFIER_SMTP_USERNAME and ADMIN_NOTIFIER_SMTP_PASSWORD must be set together")
		}
		address, parseErr := mail.ParseAddress(config.SMTPFrom)
		if parseErr != nil || address.Address != config.SMTPFrom {
			return NotifierConfig{}, errors.New("ADMIN_NOTIFIER_SMTP_FROM must be a canonical e-mail address")
		}
	case "webhook":
		rawURL := strings.TrimSpace(os.Getenv("ADMIN_NOTIFIER_WEBHOOK_URL"))
		if rawURL == "" {
			return NotifierConfig{}, errors.New("ADMIN_NOTIFIER_WEBHOOK_URL is required for the webhook channel")
		}
		parsed, parseErr := url.Parse(rawURL)
		if parseErr != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil {
			return NotifierConfig{}, errors.New("ADMIN_NOTIFIER_WEBHOOK_URL must be an absolute http(s) URL without credentials")
		}
		config.WebhookURL = parsed
	}
	return config, nil
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

func intEnv(name string, fallback, minimum, maximum int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", name, minimum, maximum)
	}
	return parsed, nil
}

// BuildChannel constructs the configured delivery channel. Configuration was
// already validated fail-closed by LoadNotifierConfig.
func (config NotifierConfig) BuildChannel() (NoticeChannel, error) {
	switch config.Channel {
	case "smtp":
		return &SMTPChannel{
			host:     config.SMTPHost,
			port:     config.SMTPPort,
			username: config.SMTPUsername,
			password: config.SMTPPassword,
			from:     config.SMTPFrom,
			tlsMode:  config.SMTPTLSMode,
		}, nil
	case "webhook":
		return &WebhookChannel{
			url:        config.WebhookURL,
			hmacSecret: config.WebhookHMACSecret,
			client:     &http.Client{Timeout: 15 * time.Second},
		}, nil
	}
	return nil, fmt.Errorf("unsupported notifier channel %q", config.Channel)
}

// DeliveryError classifies a channel failure. Permanent failures (webhook
// 4xx, SMTP 5xx recipient rejection, undeliverable payload) are settled as
// failed immediately; everything else is transient and retried with backoff
// until the attempt budget is exhausted.
type DeliveryError struct {
	Permanent bool
	Reason    string
}

func (err *DeliveryError) Error() string { return err.Reason }

func permanentDelivery(reason string) *DeliveryError {
	return &DeliveryError{Permanent: true, Reason: reason}
}

func transientDelivery(reason string) *DeliveryError {
	return &DeliveryError{Permanent: false, Reason: reason}
}

func isPermanentDelivery(err error) bool {
	var deliveryErr *DeliveryError
	return errors.As(err, &deliveryErr) && deliveryErr.Permanent
}

// NoticeChannel delivers one claimed activation notice. Implementations
// return a *DeliveryError so the worker can classify the outcome.
type NoticeChannel interface {
	Deliver(ctx context.Context, event OutboxEvent, payload ActivationNoticePayload) error
}

// SMTPChannel delivers the activation notice as an e-mail to the contact
// reference recorded by the enrollment flow. STARTTLS (default), implicit
// TLS and plain transport are supported; credentials come only from the
// environment.
type SMTPChannel struct {
	host     string
	port     int
	username string
	password string
	from     string
	tlsMode  string
}

func (channel *SMTPChannel) Deliver(ctx context.Context, event OutboxEvent, payload ActivationNoticePayload) error {
	recipient := strings.TrimSpace(payload.ContactReference)
	address, err := mail.ParseAddress(recipient)
	if err != nil || address.Address != recipient {
		return permanentDelivery(fmt.Sprintf("contact reference %q is not a deliverable e-mail address", recipient))
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	endpoint := net.JoinHostPort(channel.host, strconv.Itoa(channel.port))
	tlsConfig := &tls.Config{ServerName: channel.host, MinVersion: tls.VersionTLS12}
	var connection net.Conn
	if channel.tlsMode == "tls" {
		connection, err = tls.DialWithDialer(dialer, "tcp", endpoint, tlsConfig)
	} else {
		connection, err = dialer.DialContext(ctx, "tcp", endpoint)
	}
	if err != nil {
		return transientDelivery(fmt.Sprintf("smtp dial %s: %v", endpoint, err))
	}
	client, err := smtp.NewClient(connection, channel.host)
	if err != nil {
		_ = connection.Close()
		return classifySMTPError("session setup", err)
	}
	defer func() { _ = client.Close() }()
	if channel.tlsMode == "starttls" {
		if supported, _ := client.Extension("STARTTLS"); !supported {
			return permanentDelivery("smtp server does not offer STARTTLS and ADMIN_NOTIFIER_SMTP_TLS_MODE=starttls")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return classifySMTPError("STARTTLS", err)
		}
	}
	if channel.username != "" {
		if err := client.Auth(smtp.PlainAuth("", channel.username, channel.password, channel.host)); err != nil {
			return classifySMTPError("authentication", err)
		}
	}
	if err := client.Mail(channel.from); err != nil {
		return classifySMTPError("MAIL FROM", err)
	}
	if err := client.Rcpt(recipient); err != nil {
		return classifySMTPError("RCPT TO", err)
	}
	writer, err := client.Data()
	if err != nil {
		return classifySMTPError("DATA", err)
	}
	if _, err := io.WriteString(writer, channel.message(event, payload, recipient)); err != nil {
		_ = writer.Close()
		return transientDelivery(fmt.Sprintf("smtp message write: %v", err))
	}
	if err := writer.Close(); err != nil {
		return classifySMTPError("message commit", err)
	}
	if err := client.Quit(); err != nil {
		return classifySMTPError("QUIT", err)
	}
	return nil
}

func (channel *SMTPChannel) message(event OutboxEvent, payload ActivationNoticePayload, recipient string) string {
	var message strings.Builder
	message.WriteString("From: " + channel.from + "\r\n")
	message.WriteString("To: " + recipient + "\r\n")
	message.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	message.WriteString("Message-ID: <" + event.ID + "@admin-notifier.blueeconomy>\r\n")
	message.WriteString("Subject: Blue Economy platform access activated\r\n")
	message.WriteString("MIME-Version: 1.0\r\n")
	message.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	message.WriteString("\r\n")
	message.WriteString("Your Blue Economy platform access has been activated.\r\n\r\n")
	message.WriteString("Onboarding reference: " + payload.RequestID + "\r\n")
	message.WriteString("Activated at (UTC): " + payload.ActivatedAt.UTC().Format(time.RFC3339) + "\r\n\r\n")
	message.WriteString("Quote the onboarding reference above when signing in or contacting support.\r\n")
	message.WriteString("If you did not request this access, contact your onboarding officer immediately.\r\n")
	return message.String()
}

// classifySMTPError maps SMTP protocol replies onto the retry contract:
// 5xx replies (recipient rejection, permanent protocol failures) never
// succeed on retry and settle failed immediately; 4xx replies and network
// errors are transient.
func classifySMTPError(stage string, err error) error {
	var protocolErr *textproto.Error
	if errors.As(err, &protocolErr) {
		if protocolErr.Code >= 500 {
			return permanentDelivery(fmt.Sprintf("smtp %s rejected permanently: %d %s", stage, protocolErr.Code, protocolErr.Msg))
		}
		return transientDelivery(fmt.Sprintf("smtp %s failed transiently: %d %s", stage, protocolErr.Code, protocolErr.Msg))
	}
	return transientDelivery(fmt.Sprintf("smtp %s failed: %v", stage, err))
}

// WebhookChannel POSTs the platform-envelope activation notice JSON to the
// configured gateway endpoint (for example an SMS/USSD gateway). An optional
// HMAC-SHA256 secret signs the exact request body. 2xx settles sent, 4xx is
// a permanent rejection, everything else is transient.
type WebhookChannel struct {
	url        *url.URL
	hmacSecret string
	client     *http.Client
}

type webhookEnvelope struct {
	Topic               string          `json:"topic"`
	EventType           string          `json:"event_type"`
	Classification      string          `json:"classification"`
	ProvenancePrincipal string          `json:"provenance_principal"`
	EventID             string          `json:"event_id"`
	Payload             json.RawMessage `json:"payload"`
}

func (channel *WebhookChannel) Deliver(ctx context.Context, event OutboxEvent, _ ActivationNoticePayload) error {
	body, err := json.Marshal(webhookEnvelope{
		Topic:               event.Topic,
		EventType:           event.EventType,
		Classification:      event.Classification,
		ProvenancePrincipal: event.ProvenancePrincipal,
		EventID:             event.ID,
		Payload:             event.Payload,
	})
	if err != nil {
		return permanentDelivery(fmt.Sprintf("encode webhook payload: %v", err))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, channel.url.String(), strings.NewReader(string(body)))
	if err != nil {
		return permanentDelivery(fmt.Sprintf("build webhook request: %v", err))
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Blueeconomy-Event", event.EventType)
	request.Header.Set("X-Blueeconomy-Delivery", event.ID)
	if channel.hmacSecret != "" {
		mac := hmac.New(sha256.New, []byte(channel.hmacSecret))
		_, _ = mac.Write(body)
		request.Header.Set("X-Blueeconomy-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	response, err := channel.client.Do(request)
	if err != nil {
		return transientDelivery(fmt.Sprintf("webhook POST %s: %v", channel.url.Host, err))
	}
	defer func() { _, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096)); _ = response.Body.Close() }()
	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		return nil
	case response.StatusCode >= 400 && response.StatusCode < 500:
		return permanentDelivery(fmt.Sprintf("webhook rejected delivery permanently: HTTP %d", response.StatusCode))
	default:
		return transientDelivery(fmt.Sprintf("webhook delivery failed transiently: HTTP %d", response.StatusCode))
	}
}

// NotifierStore is the outbox lease surface the worker needs. *Store
// implements it against PostgreSQL.
type NotifierStore interface {
	ClaimOutboxEvents(ctx context.Context, limit, maxAttempts int) ([]OutboxEvent, error)
	RecordNotificationResult(ctx context.Context, eventID string, success bool, reason string) error
}

// Expvar counters, following the stdlib instrumentation convention.
var (
	notifierClaimedTotal = expvar.NewInt("admin_notifier_claimed_total")
	notifierSentTotal    = expvar.NewInt("admin_notifier_sent_total")
	notifierFailedTotal  = expvar.NewInt("admin_notifier_failed_total")
	notifierRetriedTotal = expvar.NewInt("admin_notifier_retried_total")
)

// Notifier is the outbox drain worker. It claims batches under the 60-second
// SKIP LOCKED lease, delivers each notice through the configured channel and
// settles every claimed event explicitly as sent or failed; nothing is ever
// silently dropped.
type Notifier struct {
	store        NotifierStore
	channel      NoticeChannel
	batchSize    int
	pollInterval time.Duration
	maxAttempts  int
	logger       *slog.Logger
	// inlineRetries bounds the in-lease backoff retries per claim before the
	// event is settled failed (reclaimable) for the next poll.
	inlineRetries int
	backoffBase   time.Duration
}

func NewNotifier(store NotifierStore, channel NoticeChannel, config NotifierConfig, logger *slog.Logger) *Notifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &Notifier{
		store:         store,
		channel:       channel,
		batchSize:     config.BatchSize,
		pollInterval:  config.PollInterval,
		maxAttempts:   config.MaxAttempts,
		logger:        logger,
		inlineRetries: 4,
		backoffBase:   250 * time.Millisecond,
	}
}

// Run drains the outbox until ctx is cancelled. The in-flight batch is
// finished before returning; events that cannot be settled in time keep
// their lease and are re-claimed after it expires.
func (notifier *Notifier) Run(ctx context.Context) error {
	ticker := time.NewTicker(notifier.pollInterval)
	defer ticker.Stop()
	for {
		notifier.drain(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (notifier *Notifier) drain(ctx context.Context) {
	events, err := notifier.store.ClaimOutboxEvents(ctx, notifier.batchSize, notifier.maxAttempts)
	if err != nil {
		if ctx.Err() == nil {
			notifier.logger.Error("outbox claim failed", "error", err)
		}
		return
	}
	if len(events) > 0 {
		notifier.logger.Info("claimed outbox events", "count", len(events))
	}
	for _, event := range events {
		deliveryCtx := ctx
		var cancel context.CancelFunc = func() {}
		if ctx.Err() != nil {
			// Shutdown in progress: finish the in-flight batch on a detached,
			// bounded context so settlements stay durable.
			deliveryCtx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
		}
		notifier.processEvent(deliveryCtx, event)
		cancel()
	}
}

// processEvent delivers one claimed event and always drives it to an explicit
// settlement: sent on success, failed on permanent rejection or when the
// attempt budget is exhausted, failed-but-reclaimable when the transient
// budget for this claim runs out (the next poll re-claims it).
func (notifier *Notifier) processEvent(ctx context.Context, event OutboxEvent) {
	notifierClaimedTotal.Add(1)
	log := notifier.logger.With("event_id", event.ID, "request_id", event.RequestID, "attempt", event.Attempt)
	var payload ActivationNoticePayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		log.Error("outbox event payload is undeliverable", "error", err)
		notifier.settle(ctx, log, event, false, "undeliverable activation notice payload: "+err.Error())
		return
	}
	for retry := 0; ; retry++ {
		err := notifier.channel.Deliver(ctx, event, payload)
		if err == nil {
			log.Info("activation notice delivered")
			notifier.settle(ctx, log, event, true, "")
			return
		}
		if ctx.Err() != nil {
			// The worker is stopping; leave the event claimed so its lease
			// expires and another run re-claims it.
			log.Warn("delivery interrupted by shutdown; lease left to expire", "error", err)
			return
		}
		reason := truncateNoticeError(err.Error())
		if isPermanentDelivery(err) {
			log.Error("activation notice permanently rejected", "error", err)
			notifier.settle(ctx, log, event, false, reason)
			return
		}
		if event.Attempt >= notifier.maxAttempts {
			log.Error("activation notice delivery attempts exhausted", "max_attempts", notifier.maxAttempts, "error", err)
			notifier.settle(ctx, log, event, false, fmt.Sprintf("delivery attempts exhausted (%d/%d): %s", event.Attempt, notifier.maxAttempts, reason))
			return
		}
		notifierRetriedTotal.Add(1)
		if retry >= notifier.inlineRetries {
			// Transient failure persists: settle failed (reclaimable, since
			// attempts remain) so the next poll re-claims it without waiting
			// for the lease to expire.
			log.Warn("activation notice deferred after transient failures", "error", err)
			notifier.settle(ctx, log, event, false, "transient delivery failure, will retry: "+reason)
			return
		}
		delay := notifier.backoffBase << retry
		if delay > 2*time.Second {
			delay = 2 * time.Second
		}
		log.Warn("activation notice delivery failed transiently; backing off", "retry_in", delay.String(), "error", err)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// settle records the durable outcome. A settlement error is logged loudly
// and the event keeps its lease, so a crashed or partitioned worker can
// never lose an event: it is re-claimed after the lease expires.
func (notifier *Notifier) settle(ctx context.Context, log *slog.Logger, event OutboxEvent, success bool, reason string) {
	if err := notifier.store.RecordNotificationResult(ctx, event.ID, success, truncateNoticeError(reason)); err != nil {
		log.Error("notification result could not be recorded; event will be re-claimed after lease expiry", "error", err)
		return
	}
	if success {
		notifierSentTotal.Add(1)
	} else {
		notifierFailedTotal.Add(1)
	}
}

func truncateNoticeError(message string) string {
	const limit = 2048 // onboarding_outbox_events.last_error CHECK constraint
	if len(message) <= limit {
		return message
	}
	return message[:limit]
}
