package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-sasl"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var version = ""

// OAuth2Config contains the fields required to obtain access/refresh tokens.
// Supports authorization code flow (with local redirect).
type OAuth2Config struct {
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	RefreshToken string   `yaml:"refresh_token"`
	TokenURL     string   `yaml:"token_url"`
	AuthURL      string   `yaml:"auth_url"`
	RedirectURI  string   `yaml:"redirect_uri"` // optional; if present, the listener uses the specified host:port
	Scope        []string `yaml:"scope"`
}

type ProviderConfiguration struct {
	Label    string        `yaml:"label"`
	Host     string        `yaml:"host"`
	Port     int           `yaml:"port"`
	Username string        `yaml:"username"`
	Password string        `yaml:"password"`
	Mailbox  string        `yaml:"mailbox"`
	Sound    string        `yaml:"sound"`
	Icon     string        `yaml:"icon"`
	Timeout  int32         `yaml:"timeout"`
	OAuth2   *OAuth2Config `yaml:"oauth2"`
}

type IMAPClient struct {
	Name        string `yaml:"name"`
	CommandLine string `yaml:"command_line"`
}

type GeneralConfiguration struct {
	IMAPClient IMAPClient `yaml:"imap_client"`
}

type Configuration struct {
	General   GeneralConfiguration    `yaml:"general"`
	Providers []ProviderConfiguration `yaml:"providers"`
}

// Constants for cache management
const (
	MaxSeenUIDs         = 10000 // Maximum UIDs to keep per provider
	SeenCleanupInterval = 1 * time.Hour
	MaxFetchMessages    = 1000 // Maximum messages to fetch at once
)

type SeenStatus struct {
	mu   sync.Mutex
	seen map[string]map[uint32]struct{} // key: conf.Label -> set of notified UIDs
}

func NewSeenStatus() *SeenStatus {
	return &SeenStatus{
		seen: make(map[string]map[uint32]struct{}),
	}
}

func (s *SeenStatus) markSeen(label string, uids []uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[label]; !ok {
		s.seen[label] = make(map[uint32]struct{})
	}
	for _, u := range uids {
		s.seen[label][u] = struct{}{}
	}

	// Simple cleanup: if we exceed max UIDs, remove half of them (oldest UIDs)
	if len(s.seen[label]) > MaxSeenUIDs {
		var toRemove []uint32
		count := 0
		target := MaxSeenUIDs / 2
		for uid := range s.seen[label] {
			if count >= target {
				break
			}
			toRemove = append(toRemove, uid)
			count++
		}
		for _, uid := range toRemove {
			delete(s.seen[label], uid)
		}
	}
}

func (s *SeenStatus) isSeen(label string, uid uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.seen[label][uid]
	return ok
}

func (s *SeenStatus) getSeenByLabel(label string) []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var uids []uint32
	for uid := range s.seen[label] {
		uids = append(uids, uid)
	}
	return uids
}

type NotificationMap struct {
	mu       sync.Mutex
	notified map[string]map[uint32]uint32 // key: conf.Label -> map of UID to notification ID
}

func NewNotifications() *NotificationMap {
	return &NotificationMap{
		notified: make(map[string]map[uint32]uint32),
	}
}

func (n *NotificationMap) add(label string, msgUID uint32, ntfID uint32) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.notified[label]; !ok {
		n.notified[label] = make(map[uint32]uint32)
	}
	n.notified[label][msgUID] = ntfID
}

func (n *NotificationMap) remove(log *zap.SugaredLogger, label string, msgUID uint32) {
	n.mu.Lock()
	defer n.mu.Unlock()

	notifier, err := NewNotifier()
	if err != nil {
		log.Errorf("%s: failed to initialize notifier: %v", label, err)
		os.Exit(1)
	}

	if ntfs, ok := n.notified[label]; ok {
		if ntfID, ok := ntfs[msgUID]; ok {
			delete(ntfs, msgUID)
			// Close notification via DBus
			err := notifier.CloseNotification(ntfID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error closing notification ID %d: %s\n", ntfID, err)
			}
		}
	}
}

// Constants for timeouts and intervals
const (
	DefaultHTTPTimeout   = 15 * time.Second
	DefaultOAuth2Timeout = 30 * time.Second
	IMAPKeepAlive        = 5 * time.Minute
	ReconnectDelay       = 5 * time.Second
	OAuth2FlowTimeout    = 5 * time.Minute
	IdleStopTimeout      = 5 * time.Second
	TokenExpiryMargin    = 60 * time.Second
	DefaultTokenExpiry   = 1 * time.Hour
)

// debug flags set from main
var (
	appName           string = "go-cervino"
	globalIMAPTrace   bool
	globalDebugTokens bool
	seenStatus        = NewSeenStatus()
	notifications     = NewNotifications()
)

// tokenCacheItem stores an access token and its expiration.
type tokenCacheItem struct {
	AccessToken string
	Expiry      time.Time
}

// tokenCache is a simple in-memory cache for access tokens.
var tokenCache = struct {
	sync.Mutex
	m map[string]tokenCacheItem
}{m: make(map[string]tokenCacheItem)}

// token store on disk: we only save refresh_token for provider/user/token_url
// path: $XDG_CONFIG_HOME/go-cervino/oauth_tokens.json or ~/.config/go-cervino/oauth_tokens.json
func tokenStorePath() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "go-cervino", "oauth_tokens.json")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "go-cervino", "oauth_tokens.json")
}

func loadTokenStore(log *zap.SugaredLogger) (map[string]string, error) {
	p := tokenStorePath()

	// Check file permissions for security
	if info, err := os.Stat(p); err == nil {
		mode := info.Mode()
		if mode&0o077 != 0 {
			log.Warnf("Token store file %s has unsafe permissions %o, should be 0600", p, mode)
		}
	}

	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}

	defer func() {
		err := f.Close()
		if err != nil {
			log.Errorf("Error closing token store file: %s", err)
		}
	}()

	m := map[string]string{}
	dec := json.NewDecoder(f)
	if err := dec.Decode(&m); err != nil && err != io.EOF {
		return nil, err
	}
	return m, nil
}

func saveTokenStore(log *zap.SugaredLogger, m map[string]string) error {
	p := tokenStorePath()
	d := filepath.Dir(p)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}

	defer func() {
		err := f.Close()
		if err != nil {
			log.Errorf("Error closing token store file: %s", err)
		}
	}()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}

// ===== OAuth2 helpers =====
func b64url(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), "=")
}

func genCodeVerifier() (string, error) {
	r := make([]byte, 64)
	if _, err := rand.Read(r); err != nil {
		return "", err
	}
	return b64url(r), nil
}

func codeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64url(sum[:])
}

// getAccessTokenFromRefreshToken: obtains access token from refresh token.
func getAccessTokenFromRefreshToken(ctx context.Context, log *zap.SugaredLogger, oauth *OAuth2Config) (string, time.Time, error) {
	if oauth.TokenURL == "" {
		return "", time.Time{}, fmt.Errorf("token_url not set in OAuth2 configuration")
	}
	form := url.Values{}
	form.Set("client_id", oauth.ClientID)
	if oauth.ClientSecret != "" {
		form.Set("client_secret", oauth.ClientSecret)
	}
	form.Set("refresh_token", oauth.RefreshToken)
	form.Set("grant_type", "refresh_token")
	if len(oauth.Scope) > 0 {
		form.Set("scope", strings.Join(oauth.Scope, " "))
	}
	req, err := http.NewRequestWithContext(ctx, "POST", oauth.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpClient := &http.Client{Timeout: DefaultHTTPTimeout}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Errorf("Error closing response body: %s", err)
		}
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.ReadAll(resp.Body) // Read and discard body to prevent information leakage
		return "", time.Time{}, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", time.Time{}, err
	}
	expiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	if tokenResp.ExpiresIn == 0 {
		expiry = time.Now().Add(DefaultTokenExpiry)
	}
	return tokenResp.AccessToken, expiry, nil
}

// fetchAccessToken: cache + refresh + migration of legacy key
func fetchAccessToken(ctx context.Context, log *zap.SugaredLogger, label, username string, oauth *OAuth2Config) (string, error) {
	primaryKey := oauth.TokenURL + "|" + username + "|" + label
	legacyKey := oauth.TokenURL + "||" + label
	if oauth.RefreshToken == "" {
		if store, err := loadTokenStore(log); err == nil {
			if v, ok := store[primaryKey]; ok {
				oauth.RefreshToken = v
			} else if v, ok := store[legacyKey]; ok {
				oauth.RefreshToken = v
			}
		}
	}
	tokenCache.Lock()
	item, ok := tokenCache.m[primaryKey]
	tokenCache.Unlock()
	const margin = TokenExpiryMargin
	if ok && time.Now().Add(margin).Before(item.Expiry) && item.AccessToken != "" {
		return item.AccessToken, nil
	}
	if oauth.RefreshToken == "" {
		return "", fmt.Errorf("no refresh token available for provider %s user %s", label, username)
	}
	accessToken, expiry, err := getAccessTokenFromRefreshToken(ctx, log, oauth)
	if err != nil {
		return "", err
	}
	tokenCache.Lock()
	tokenCache.m[primaryKey] = tokenCacheItem{AccessToken: accessToken, Expiry: expiry}
	tokenCache.Unlock()
	return accessToken, nil
}

// SASL XOAUTH2
type xoauth2Client struct {
	username, token string
	started         bool
}

func NewXOAuth2(username, token string) sasl.Client {
	return &xoauth2Client{username: username, token: token}
}

func (c *xoauth2Client) Start() (string, []byte, error) {
	ir := []byte("user=" + c.username + "\x01auth=Bearer " + c.token + "\x01\x01")
	c.started = true
	return "XOAUTH2", ir, nil
}
func (c *xoauth2Client) Next(challenge []byte) ([]byte, error) { return nil, nil }

type sideWriter struct {
	prefix string
	dst    io.Writer
}

func (w sideWriter) Write(p []byte) (int, error) {
	fmt.Fprintf(os.Stderr, "--- [%s] -------------------------------------------------------------------\n", w.prefix)
	_ = os.Stderr.Sync()
	n, err := w.dst.Write(p)
	fmt.Fprintf(os.Stderr, "================================================================================\n")
	_ = os.Stderr.Sync()
	return n, err
}

func enableIMAPTrace(c *client.Client, log *zap.SugaredLogger) {
	local := sideWriter{prefix: "CLIENT", dst: os.Stderr}
	remote := sideWriter{prefix: "SERVER", dst: os.Stderr}
	dw := imap.NewDebugWriter(local, remote)
	c.SetDebug(dw)
	log.Infof("IMAP trace enabled")
}

// Decoding (without verification) of the JWT payload to log aud/scp
func logTokenClaims(log *zap.SugaredLogger, accessToken string) {
	parts := strings.Split(accessToken, ".")
	if len(parts) < 2 {
		log.Debug("token does not appear to be a JWT")
		return
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Debugf("unable to decode JWT payload: %v", err)
		return
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		log.Debugf("JWT payload is not JSON: %v", err)
		return
	}
	aud, _ := m["aud"].(string)
	scp, _ := m["scp"].(string)
	app, _ := m["appid"].(string)
	upn, _ := m["upn"].(string)
	if upn == "" {
		upn, _ = m["preferred_username"].(string)
	}
	log.Debugf("JWT aud=%q scp=%q appid=%q user=%q", aud, scp, app, upn)
}

func fetchUnseenUIDs(c *client.Client) ([]uint32, error) {
	criteria := imap.NewSearchCriteria()
	criteria.WithoutFlags = []string{imap.SeenFlag}
	return c.UidSearch(criteria)
}

func fetchByUIDs(c *client.Client, uids []uint32) ([]*imap.Message, error) {
	if len(uids) == 0 {
		return nil, nil
	}

	// Limit the number of messages fetched at once to prevent memory issues
	if len(uids) > MaxFetchMessages {
		uids = uids[:MaxFetchMessages]
	}

	seqset := new(imap.SeqSet)
	for _, u := range uids {
		seqset.AddNum(u)
	}

	items := []imap.FetchItem{imap.FetchEnvelope, imap.FetchFlags, imap.FetchInternalDate, imap.FetchUid}
	ch := make(chan *imap.Message, len(uids)) // Buffer size based on actual UIDs
	done := make(chan error, 1)
	go func() { done <- c.UidFetch(seqset, items, ch) }()
	var out []*imap.Message
	for m := range ch {
		if m != nil {
			out = append(out, m)
		}
	}
	if err := <-done; err != nil {
		return nil, err
	}
	return out, nil
}

func notifyNewUIDs(log *zap.SugaredLogger, conf ProviderConfiguration, msgs []*imap.Message, imapClient IMAPClient) {
	var newly []uint32

	notifier, err := NewNotifier()
	if err != nil {
		log.Errorf("%s: failed to initialize notifier: %v", conf.Label, err)
		os.Exit(1)
	}

	for _, msg := range msgs {
		uid := msg.Uid
		if seenStatus.isSeen(conf.Label, uid) {
			continue
		}
		isNew := true
		for _, f := range msg.Flags {
			if f == imap.SeenFlag {
				isNew = false
				break
			}
		}
		if !isNew {
			continue
		}

		fromName := ""
		if len(msg.Envelope.From) > 0 && msg.Envelope.From[0] != nil {
			fromName = msg.Envelope.From[0].PersonalName
		}

		subject := msg.Envelope.Subject
		if subject == "" {
			subject = "(no subject)"
		}
		safeSubject := strings.ReplaceAll(strings.ReplaceAll(subject, "<", "&lt;"), ">", "&gt;")
		safeFromName := strings.ReplaceAll(strings.ReplaceAll(fromName, "<", "&lt;"), ">", "&gt;")

		icon := conf.Icon
		if icon == "" {
			icon = "mail-unread"
		}
		timeout := int32(0)
		if conf.Timeout > 0 {
			timeout = conf.Timeout * 1000
		}

		// actions are: key1, label1, key2, label2, ...
		actions := []string{
			"open",
			"Open in " + imapClient.Name,
		}

		// Show notification via DBus
		notificationID, err := notifier.ShowNotification(
			"New email in "+conf.Label,
			fmt.Sprintf("<b>%s</b> from <i>%s</i>", safeSubject, safeFromName),
			icon,
			actions,
			timeout,
			func(action string) {
				if action == "open" {
					fields := strings.Fields(imapClient.CommandLine)
					if len(fields) == 0 {
						log.Errorf("%s: IMAP client command line is empty", conf.Label)
						return
					}
					cmd := exec.Command(fields[0], fields[1:]...)
					err2 := cmd.Start()
					if err2 != nil {
						log.Errorf("%s: failed to execute IMAP client command \"%s\": %v", conf.Label, imapClient.CommandLine, err2)
						return
					}
					go func() {
						_ = cmd.Wait()
						log.Debugf("%s: IMAP client (%s) process exited", conf.Label, imapClient.Name)
					}()
				}
			},
		)
		if err == nil {
			notifications.add(conf.Label, uid, notificationID)
			log.Infof("%s: new email notification shown (message UID %d)", conf.Label, uid)
			log.Infof("%s:     Subject: %s", conf.Label, subject)
			log.Infof("%s:     From: %s", conf.Label, fromName)
		} else {
			log.Errorf("%s: failed to show notification for UID %d: %v", conf.Label, uid, err)
		}

		newly = append(newly, uid)
	}
	if len(newly) > 0 {
		seenStatus.markSeen(conf.Label, newly)
	}
	printMessages(log, conf, msgs)
}

func withTimeout(timeout time.Duration, fn func() error) error {
	ctxTimeout, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- fn()
	}()

	select {
	case err := <-done:
		return err
	case <-ctxTimeout.Done():
		switch ctxTimeout.Err() {
		case context.DeadlineExceeded:
			return fmt.Errorf("operation timed out after %s", timeout) // Caso 2: timeout locale
		default:
			return fmt.Errorf("unknown context error: %w", ctxTimeout.Err())
		}
	}
}

func startIdle(c *client.Client) func() error {
	stopIdle := make(chan struct{})
	doneIdle := make(chan error, 1)

	go func() { doneIdle <- c.Idle(stopIdle, nil) }()

	return func() error {
		return withTimeout(IdleStopTimeout, func() error {
			close(stopIdle)
			return <-doneIdle
		})
	}
}

func printMailboxStatus(log *zap.SugaredLogger, msg string, conf ProviderConfiguration, mboxStatus *imap.MailboxStatus) {
	log.Debugf("%s: %s", conf.Label, msg)
	log.Debugf("%s: Mailbox update: %d messages, %d recent, %d unseen, %d unseenSeqNum",
		conf.Label, mboxStatus.Messages, mboxStatus.Recent, mboxStatus.Unseen, mboxStatus.UnseenSeqNum)
}

func printMessage(log *zap.SugaredLogger, conf ProviderConfiguration, msg imap.Message) {
	log.Debugf("%s: EMAIL %d", conf.Label, msg.SeqNum)
	log.Debugf("%s: \tDATE = %s", conf.Label, msg.Envelope.Date)
	log.Debugf("%s: \tSUBJECT = %s", conf.Label, msg.Envelope.Subject)
	for i, f := range msg.Envelope.From {
		log.Debugf("%s: \tFROM[%d] = \"%s\" <%s@%s>", conf.Label, i+1, f.PersonalName, f.MailboxName, f.HostName)
	}
	for i, f := range msg.Flags {
		log.Debugf("%s: \tFLAG[%d] = %s", conf.Label, i+1, f)
	}
	log.Debugf("%s: \tMESSAGE-ID = %s", conf.Label, msg.Envelope.MessageId)
}

func printMessages(log *zap.SugaredLogger, conf ProviderConfiguration, messages []*imap.Message) {
	for _, msg := range messages {
		printMessage(log, conf, *msg)
	}
}

func runIMAPClient(ctx context.Context, log *zap.SugaredLogger, conf ProviderConfiguration, imapClient IMAPClient) {
	keepAlive := IMAPKeepAlive
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		log.Debugf("Connecting to \"%s\"...", conf.Label)
		addr := fmt.Sprintf("%s:%d", conf.Host, conf.Port)
		c, err := client.DialTLS(addr, nil)
		if err != nil {
			log.Errorf("%s: connection error: %v", conf.Label, err)
			time.Sleep(ReconnectDelay)
			continue
		}

		if globalIMAPTrace {
			enableIMAPTrace(c, log)
		}

		log.Debugf("...%s connected", conf.Label)
		if conf.OAuth2 != nil {
			if strings.TrimSpace(conf.Username) == "" {
				log.Errorf("%s: missing username: XOAUTH2 requires the full email address (e.g. user@domain)", conf.Label)
				_ = c.Logout()
				time.Sleep(5 * time.Second)
				continue
			}
			tctx, cancel := context.WithTimeout(ctx, DefaultOAuth2Timeout)
			var token string
			token, err = fetchAccessToken(tctx, log, conf.Label, conf.Username, conf.OAuth2)
			cancel()
			if err != nil {
				log.Errorf("%s: cannot get OAuth2 token: %v", conf.Label, err)
				_ = c.Logout()
				time.Sleep(ReconnectDelay)
				continue
			}
			if globalDebugTokens {
				logTokenClaims(log, token)
			}
			log.Debugf("%s: XOAUTH2 user=%q", conf.Label, conf.Username)
			auth := NewXOAuth2(conf.Username, token)
			if err = c.Authenticate(auth); err != nil {
				log.Errorf("%s: OAuth2 auth failed: %v", conf.Label, err)
				log.Infof("Tip: start with --imap-trace to see the IMAP dialog.")
				_ = c.Logout()
				time.Sleep(ReconnectDelay)
				cacheKey := conf.OAuth2.TokenURL + "|" + conf.Username + "|" + conf.Label
				tokenCache.Lock()
				delete(tokenCache.m, cacheKey)
				tokenCache.Unlock()
				continue
			}
		} else {
			if err = c.Login(conf.Username, conf.Password); err != nil {
				log.Errorf("%s: login error: %v", conf.Label, err)
				_ = c.Logout()
				time.Sleep(ReconnectDelay)
				continue
			}
		}
		log.Debugf("%s logged in", conf.Label)

		if conf.Mailbox == "" {
			conf.Mailbox = "INBOX"
		}

		uids, err := fetchUnseenUIDs(c)
		if err == nil && len(uids) > 0 {
			seenStatus.markSeen(conf.Label, uids)
		}

		updates := make(chan client.Update, 1024)
		c.Updates = updates
		inboxStatus, err := c.Select(conf.Mailbox, true)
		if err != nil {
			log.Errorf("%s: select mailbox error: %v", conf.Label, err)
			continue
		}
		printMailboxStatus(log, "Mailbox selected", conf, inboxStatus)
		stopIdle := startIdle(c)

	loop:
		for {
			select {
			case <-ctx.Done():
				log.Infof("%s: signal received, shutting down client", conf.Label)
				_ = stopIdle()
				_ = c.Terminate()
				return
			case update, ok := <-updates:
				if !ok {
					break loop
				}
				err := stopIdle()
				if err != nil {
					log.Errorf("%s: error stopping idle: %v", conf.Label, err)
					_ = c.Terminate()
					break loop
				}
				switch update := update.(type) {
				case *client.MailboxUpdate:
					uids, err = fetchUnseenUIDs(c)
					if err != nil {
						log.Errorf("%s: search unseen error: %v", conf.Label, err)
						break loop
					}
					var toFetch []uint32
					for _, u := range uids {
						if !seenStatus.isSeen(conf.Label, u) {
							toFetch = append(toFetch, u)
						}
					}
					msgs, err := fetchByUIDs(c, toFetch)
					if err != nil {
						log.Errorf("%s: fetch by uid error: %v", conf.Label, err)
						break loop
					}
					notifyNewUIDs(log, conf, msgs, imapClient)
				case *client.ExpungeUpdate:
					log.Debugf("%s: expunge update: %d", conf.Label, update.SeqNum)
					seenUids := seenStatus.getSeenByLabel(conf.Label)
					stillPresentUids, err := fetchUnseenUIDs(c)
					if err != nil {
						log.Errorf("%s: search unseen error: %v", conf.Label, err)
						break loop
					}
					missingUIDs := make([]uint32, 0)
					// Now we populate missingUIDs with UIDs that were seen but are no longer present
					presentSet := make(map[uint32]struct{}, len(stillPresentUids))
					for _, u := range stillPresentUids {
						presentSet[u] = struct{}{}
					}
					for _, u := range seenUids {
						if _, ok := presentSet[u]; !ok {
							missingUIDs = append(missingUIDs, u)
						}
					}

					if len(missingUIDs) > 0 {
						log.Debugf("%s: detected %d missing UIDs after expunge: %v", conf.Label, len(missingUIDs), missingUIDs)
						for _, mu := range missingUIDs {
							notifications.remove(log, conf.Label, mu)
						}
					}
				}
				stopIdle = startIdle(c)
			case <-time.After(keepAlive):
				err := stopIdle()
				if err != nil {
					log.Errorf("%s: error stopping idle: %v", conf.Label, err)
					_ = c.Terminate()
					break loop
				}
				stopIdle = startIdle(c)
			}
		}
		if ctx.Err() != nil {
			_ = c.Terminate()
			return
		} else {
			_ = withTimeout(3*time.Second, func() error {
				return c.Logout()
			})
		}
		time.Sleep(ReconnectDelay)
	}
}

func tryPasswordLogin(conf ProviderConfiguration, log *zap.SugaredLogger) error {
	addr := fmt.Sprintf("%s:%d", conf.Host, conf.Port)
	c, err := client.DialTLS(addr, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err := c.Logout(); err != nil {
			log.Errorf("Error logging out: %s", err)
		}
	}()
	return c.Login(conf.Username, conf.Password)
}

// openBrowser opens the URL in the system browser (best effort)
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", url).Start()
	default:
		return fmt.Errorf("unsupported platform for auto-open")
	}
}

// Authorization Code Flow with local listener + PKCE when client_secret is empty
func runOAuth2Flow(log *zap.SugaredLogger, conf ProviderConfiguration, autoOpen bool) error {
	if conf.OAuth2 == nil {
		return fmt.Errorf("no oauth2 configuration")
	}
	oauth := conf.OAuth2
	if oauth.ClientID == "" || oauth.AuthURL == "" || oauth.TokenURL == "" {
		return fmt.Errorf("oauth2 configuration incomplete: client_id, auth_url and token_url are required")
	}

	listenerHost := "127.0.0.1"
	listenerPort := 0
	cbPath := "/callback"
	redirectURI := oauth.RedirectURI
	if redirectURI != "" {
		u, err := url.Parse(redirectURI)
		if err != nil {
			return fmt.Errorf("invalid redirect_uri: %v", err)
		}
		if u.Host == "" {
			return fmt.Errorf("redirect_uri must include host:port, got %s", redirectURI)
		}
		host, portStr, err := net.SplitHostPort(u.Host)
		if err != nil {
			return fmt.Errorf("redirect_uri must include explicit port: %v", err)
		}
		if host != "localhost" && host != "127.0.0.1" {
			return fmt.Errorf("redirect_uri host must be localhost or 127.0.0.1; got %s", host)
		}
		listenerHost = "127.0.0.1"
		p, err := strconv.Atoi(portStr)
		if err != nil || p <= 0 {
			return fmt.Errorf("invalid redirect_uri port: %s", portStr)
		}
		listenerPort = p
		if u.Path != "" {
			cbPath = u.Path
		}
	}
	addr := fmt.Sprintf("%s:%d", listenerHost, listenerPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("cannot open listener on %s: %v", addr, err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			log.Errorf("Error closing listener: %s", err)
		}
	}()
	if redirectURI == "" {
		addr := ln.Addr()
		tcpAddr, ok := addr.(*net.TCPAddr)
		if !ok {
			return fmt.Errorf("listener address is not TCP: %T", addr)
		}
		port := tcpAddr.Port
		redirectURI = fmt.Sprintf("http://127.0.0.1:%d%s", port, cbPath)
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", oauth.ClientID)
	q.Set("redirect_uri", redirectURI)
	if len(oauth.Scope) > 0 {
		q.Set("scope", strings.Join(oauth.Scope, " "))
	}
	q.Set("access_type", "offline")
	q.Set("prompt", "consent")
	usePKCE := oauth.ClientSecret == ""
	var codeVerifier string
	if usePKCE {
		var err error
		codeVerifier, err = genCodeVerifier()
		if err != nil {
			return fmt.Errorf("cannot generate PKCE verifier: %w", err)
		}
		q.Set("code_challenge", codeChallengeS256(codeVerifier))
		q.Set("code_challenge_method", "S256")
	}
	authURL := oauth.AuthURL + "?" + q.Encode()
	mux := http.NewServeMux()
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	mux.HandleFunc(cbPath, func(w http.ResponseWriter, r *http.Request) {
		vals := r.URL.Query()
		if e := vals.Get("error"); e != "" {
			http.Error(w, "authorization error: "+e, http.StatusBadRequest)
			select {
			case errCh <- fmt.Errorf("authorization error: %s", e):
			default:
			}
			return
		}
		code := vals.Get("code")
		if code == "" {
			http.Error(w, "no code in request", http.StatusBadRequest)
			select {
			case errCh <- fmt.Errorf("no code in request"):
			default:
			}
			return
		}
		_, _ = io.WriteString(w, "Authentication completed. You can close this window and return to the terminal.\n")
		select {
		case codeCh <- code:
		default:
		}
	})
	server := &http.Server{Handler: mux}
	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			select {
			case errCh <- err:
			default:
			}
		}
	}()
	fmt.Printf("Open the following URL in your browser and grant access:\n%s\n", authURL)
	fmt.Printf("If possible, you will be redirected to %s\n", redirectURI)
	if autoOpen {
		_ = openBrowser(authURL)
	}
	select {
	case code := <-codeCh:
		_ = server.Shutdown(context.Background())
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", redirectURI)
		form.Set("client_id", oauth.ClientID)
		if usePKCE {
			form.Set("code_verifier", codeVerifier)
		} else if oauth.ClientSecret != "" {
			form.Set("client_secret", oauth.ClientSecret)
		}
		req, err := http.NewRequest("POST", oauth.TokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		hc := &http.Client{Timeout: DefaultHTTPTimeout}
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer func() {
			if err = resp.Body.Close(); err != nil {
				log.Errorf("Error closing response body: %s", err)
			}
		}()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_, _ = io.ReadAll(resp.Body) // Read and discard body to prevent information leakage
			return fmt.Errorf("token endpoint returned %d", resp.StatusCode)
		}
		var tr struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int64  `json:"expires_in"`
		}
		if err = json.NewDecoder(resp.Body).Decode(&tr); err != nil {
			return err
		}
		cacheKey := oauth.TokenURL + "|" + conf.Username + "|" + conf.Label
		store, err := loadTokenStore(log)
		if err != nil {
			return err
		}
		if tr.RefreshToken != "" {
			store[cacheKey] = tr.RefreshToken
			delete(store, oauth.TokenURL+"||"+conf.Label)
			if err := saveTokenStore(log, store); err != nil {
				return err
			}
		}
		if tr.RefreshToken != "" {
			oauth.RefreshToken = tr.RefreshToken
		}
		return nil
	case err := <-errCh:
		_ = server.Close()
		return err
	case <-time.After(OAuth2FlowTimeout):
		_ = server.Close()
		return fmt.Errorf("timeout waiting for authorization code")
	}
}

func main() {
	config := zap.NewDevelopmentConfig()
	level := zap.NewAtomicLevel()
	level.SetLevel(zap.InfoLevel)
	config.Level = level
	logger, _ := config.Build()
	defer func() {
		_ = logger.Sync()
	}()
	log := logger.Sugar()

	var configuration Configuration
	var confFile string
	var debug bool
	var doLogin bool
	var openAuthURL bool
	var imapTrace bool
	var showVersion bool

	flag.StringVar(&confFile, "c", "config.yaml", "Configuration file")
	flag.StringVar(&confFile, "configuration", "config.yaml", "Configuration file")
	flag.BoolVar(&debug, "d", false, "Debug mode")
	flag.BoolVar(&doLogin, "login", false, "Perform interactive login (authorization code) for all providers and exit")
	flag.BoolVar(&openAuthURL, "open-browser", false, "Try to automatically open the browser during login")
	flag.BoolVar(&imapTrace, "imap-trace", false, "Print IMAP dialog")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(getVersion())
		return
	}

	if debug {
		level.SetLevel(zap.DebugLevel)
	}

	globalIMAPTrace = imapTrace
	log.Infof("Starting %s", appName)

	// Validate configuration file path for security
	if strings.Contains(confFile, "..") {
		log.Fatalf("Configuration file path cannot contain '..': %s", confFile)
	}

	data, err := os.ReadFile(confFile)
	if err != nil {
		log.Fatalf("Error reading configuration file: %s", err)
	}
	if err = yaml.Unmarshal(data, &configuration); err != nil {
		log.Fatalf("Error parsing configuration file: %s", err)
	}

	// Validate configuration for security issues
	for i, conf := range configuration.Providers {
		if strings.TrimSpace(conf.Label) == "" {
			log.Fatalf("Provider %d: label cannot be empty", i)
		}
		if strings.TrimSpace(conf.Host) == "" {
			log.Fatalf("Provider %s: host cannot be empty", conf.Label)
		}
		if conf.Port <= 0 || conf.Port > 65535 {
			log.Fatalf("Provider %s: invalid port %d", conf.Label, conf.Port)
		}
		if conf.OAuth2 != nil {
			if conf.OAuth2.RedirectURI != "" {
				if u, err := url.Parse(conf.OAuth2.RedirectURI); err != nil ||
					(u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1") {
					log.Fatalf("Provider %s: redirect_uri must be localhost or 127.0.0.1", conf.Label)
				}
			}
		}
	}

	if doLogin {
		for _, conf := range configuration.Providers {
			if conf.OAuth2 != nil {
				log.Infof("%s: starting authorization code flow...", conf.Label)
				if err := runOAuth2Flow(log, conf, openAuthURL); err != nil {
					log.Errorf("%s: OAuth2 login failed: %v", conf.Label, err)
				} else {
					log.Infof("%s: OAuth2 login completed", conf.Label)
				}
			} else {
				log.Infof("%s: testing login username/password...", conf.Label)
				if err := tryPasswordLogin(conf, log); err != nil {
					log.Errorf("%s: login failed: %v", conf.Label, err)
				} else {
					log.Infof("%s: password login successful", conf.Label)
				}
			}
		}
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	var wg sync.WaitGroup
	for _, conf := range configuration.Providers {
		wg.Add(1)
		go func(c ProviderConfiguration) {
			defer wg.Done()
			runIMAPClient(ctx, log, c, configuration.General.IMAPClient)
		}(conf)
	}

	wg.Wait()
	log.Infof("go-cervino exiting, goodbye!")
}

func getVersion() string {
	if version != "" {
		return version
	}
	cmd := exec.Command("git", "describe", "--tags", "--dirty", "--always")
	cmd.Dir = "."
	out, err := cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return "unknown"
}
