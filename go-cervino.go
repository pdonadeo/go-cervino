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
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TheCreeper/go-notify"
	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-sasl"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// OAuth2Config contiene i campi necessari per ottenere access/refresh token.
// Supporta sia authorization code flow (con redirect locale) sia device code flow.
type OAuth2Config struct {
	ClientID      string   `yaml:"client_id"`
	ClientSecret  string   `yaml:"client_secret"`
	RefreshToken  string   `yaml:"refresh_token"`
	TokenURL      string   `yaml:"token_url"`
	AuthURL       string   `yaml:"auth_url"`
	RedirectURI   string   `yaml:"redirect_uri"`    // opzionale; se presente, il listener usa host:porta indicati
	DeviceCodeURL string   `yaml:"device_code_url"` // opzionale: device authorization flow
	Scope         []string `yaml:"scope"`
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

type Configuration struct {
	Providers []ProviderConfiguration `yaml:"providers"`
}

var appName = "go-cervino"

// debug flags set from main
var (
	globalIMAPTrace   bool
	globalDebugTokens bool
)

// tokenCacheItem mantiene un access token e la scadenza.
type tokenCacheItem struct {
	AccessToken string
	Expiry      time.Time
}

// cache in memoria per token
var tokenCache = struct {
	sync.Mutex
	m map[string]tokenCacheItem
}{m: make(map[string]tokenCacheItem)}

// token store su disco: salviamo solo refresh_token per provider/user/token_url
// percorso: $XDG_CONFIG_HOME/go-cervino/oauth_tokens.json oppure ~/.config/go-cervino/oauth_tokens.json
func tokenStorePath() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "go-cervino", "oauth_tokens.json")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "go-cervino", "oauth_tokens.json")
}

func loadTokenStore(log *zap.SugaredLogger) (map[string]string, error) {
	p := tokenStorePath()
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
	f, err := os.Create(p)
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

func keys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
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

func printMessages(log *zap.SugaredLogger, conf ProviderConfiguration, messages map[uint32]imap.Message) {
	k := keys(messages)
	sort.Slice(k, func(i, j int) bool { return k[i] < k[j] })
	for _, seq := range k {
		printMessage(log, conf, messages[seq])
	}
}

func printMailboxStatus(log *zap.SugaredLogger, msg string, conf ProviderConfiguration, mboxStatus *imap.MailboxStatus) {
	log.Debugf("%s: %s", conf.Label, msg)
	log.Debugf("%s: Mailbox update: %d messages, %d recent, %d unseen, %d unseenSeqNum", conf.Label, mboxStatus.Messages, mboxStatus.Recent, mboxStatus.Unseen, mboxStatus.UnseenSeqNum)
}

func updateMessagesMap(log *zap.SugaredLogger, conf ProviderConfiguration, mboxMap map[uint32]imap.Message, mboxStatus *imap.MailboxStatus, c *client.Client, alsoNewMessages bool) (map[uint32]imap.Message, error) {
	printMailboxStatus(log, "UpdateMessageMap", conf, mboxStatus)
	if mboxStatus.Messages == 0 {
		log.Debugf("%s: UpdateMessageMap: mboxStatus.Messages == 0", conf.Label)
		return mboxMap, nil
	}
	var from uint32
	if alsoNewMessages {
		from = 1
	} else {
		if mboxStatus.UnseenSeqNum == 0 {
			from = 1
		} else {
			from = mboxStatus.UnseenSeqNum
		}
	}
	to := mboxStatus.Messages
	log.Debugf("%s: UpdateMessageMap: from=%d to=%d", conf.Label, from, to)
	seqset := new(imap.SeqSet)
	seqset.AddRange(from, to)
	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)
	go func() { done <- c.Fetch(seqset, []imap.FetchItem{imap.FetchAll}, messages) }()
	for msg := range messages {
		if msg == nil {
			continue
		}
		if _, exists := mboxMap[msg.SeqNum]; !exists {
			mboxMap[msg.SeqNum] = *msg
			isRecent := false
			for _, f := range msg.Flags {
				if f == imap.RecentFlag {
					isRecent = true
					break
				}
			}
			isNew := true
			for _, f := range msg.Flags {
				if f == imap.SeenFlag {
					isNew = false
					break
				}
			}
			if (alsoNewMessages && isNew) || isRecent {
				fromName := ""
				if len(msg.Envelope.From) > 0 {
					fromName = msg.Envelope.From[0].PersonalName
				}
				ntf := notify.NewNotification("New email in "+conf.Label, fmt.Sprintf("<b>%s</b> from <i>%s</i>", msg.Envelope.Subject, fromName))
				ntf.AppName = appName
				if conf.Icon == "" {
					ntf.AppIcon = "mail-unread"
				} else {
					ntf.AppIcon = conf.Icon
				}
				if conf.Timeout > 0 {
					ntf.Timeout = conf.Timeout * 1000
				} else {
					ntf.Timeout = notify.ExpiresNever
				}
				ntf.Hints = make(map[string]interface{})
				if conf.Sound != "" {
					ntf.Hints[notify.HintSoundFile] = conf.Sound
				}
				_, _ = ntf.Show()
			}
		}
	}
	if err := <-done; err != nil {
		return nil, err
	}
	printMessages(log, conf, mboxMap)
	return mboxMap, nil
}

func expunge(log *zap.SugaredLogger, conf ProviderConfiguration, mboxMap map[uint32]imap.Message, seqNum uint32) map[uint32]imap.Message {
	k := keys(mboxMap)
	sort.Slice(k, func(i, j int) bool { return k[i] < k[j] })
	newMboxMap := make(map[uint32]imap.Message)
	newSeqNum := uint32(1)
	for _, key := range k {
		msg := mboxMap[key]
		if msg.SeqNum != seqNum {
			msg.SeqNum = newSeqNum
			newMboxMap[newSeqNum] = msg
			newSeqNum++
		}
	}
	printMessages(log, conf, newMboxMap)
	return newMboxMap
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

// getAccessTokenFromRefreshToken: ottiene access token da refresh token.
func getAccessTokenFromRefreshToken(ctx context.Context, log *zap.SugaredLogger, oauth *OAuth2Config) (string, time.Time, error) {
	if oauth.TokenURL == "" {
		return "", time.Time{}, fmt.Errorf("token_url non impostato in configurazione OAuth2")
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
	httpClient := &http.Client{Timeout: 15 * time.Second}
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
		body, _ := io.ReadAll(resp.Body)
		return "", time.Time{}, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
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
		expiry = time.Now().Add(1 * time.Hour)
	}
	return tokenResp.AccessToken, expiry, nil
}

// fetchAccessToken: cache + refresh + migrazione chiave legacy
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
	const margin = 60 * time.Second
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

// IMAP trace redaction
type redactingWriter struct{ dst io.Writer }

func (w redactingWriter) Write(p []byte) (int, error) {
	line := string(p)
	if strings.Contains(line, "AUTHENTICATE XOAUTH2") || strings.Contains(line, "Bearer ") {
		line = redactBearer(line)
	}
	return w.dst.Write([]byte(line))
}

func redactBearer(s string) string {
	if i := strings.Index(s, "Bearer "); i != -1 {
		prefix := s[:i+7]
		rest := s[i+7:]
		if j := strings.Index(rest, "\r\n"); j != -1 {
			rest = rest[:j]
		}
		if len(rest) > 8 {
			rest = rest[:8]
		}
		return prefix + rest + "… [REDACTED]\r\n"
	}
	return s
}

func enableIMAPTrace(c *client.Client, log *zap.SugaredLogger) {
	if setter, ok := interface{}(c).(interface{ SetDebug(w io.Writer) }); ok {
		setter.SetDebug(redactingWriter{dst: os.Stderr})
		log.Infof("IMAP trace attivato (token redatti)")
	}
}

// Decodifica (senza verifica) del payload JWT per loggare aud/scp
func logTokenClaims(log *zap.SugaredLogger, accessToken string) {
	parts := strings.Split(accessToken, ".")
	if len(parts) < 2 {
		log.Debug("token non sembra un JWT")
		return
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Debugf("impossibile decodificare payload JWT: %v", err)
		return
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		log.Debugf("payload JWT non JSON: %v", err)
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

func runIMAPClient(ctx context.Context, log *zap.SugaredLogger, conf ProviderConfiguration) {
	keepAlive := 5 * time.Minute
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
			time.Sleep(5 * time.Second)
			continue
		}
		if globalIMAPTrace {
			enableIMAPTrace(c, log)
		}
		log.Debugf("...%s connected", conf.Label)
		if conf.OAuth2 != nil {
			if strings.TrimSpace(conf.Username) == "" {
				log.Errorf("%s: username mancante: XOAUTH2 richiede l'indirizzo email completo (es. user@domain)", conf.Label)
				_ = c.Logout()
				time.Sleep(5 * time.Second)
				continue
			}
			tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			var token string
			token, err = fetchAccessToken(tctx, log, conf.Label, conf.Username, conf.OAuth2)
			cancel()
			if err != nil {
				log.Errorf("%s: cannot get OAuth2 token: %v", conf.Label, err)
				_ = c.Logout()
				time.Sleep(5 * time.Second)
				continue
			}
			if globalDebugTokens {
				logTokenClaims(log, token)
			}
			log.Debugf("%s: XOAUTH2 user=%q (token redatto)", conf.Label, conf.Username)
			auth := NewXOAuth2(conf.Username, token)
			if err = c.Authenticate(auth); err != nil {
				log.Errorf("%s: OAuth2 auth failed: %v", conf.Label, err)
				log.Infof("Suggerimento: avvia con --imap-trace per vedere il dialogo IMAP (token redatti).")
				_ = c.Logout()
				time.Sleep(5 * time.Second)
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
				time.Sleep(5 * time.Second)
				continue
			}
		}
		log.Debugf("%s logged in", conf.Label)
		if conf.Mailbox == "" {
			conf.Mailbox = "INBOX"
		}
		inboxStatus, err := c.Select(conf.Mailbox, true)
		if err != nil {
			log.Errorf("%s: select error: %v", conf.Label, err)
			_ = c.Logout()
			time.Sleep(5 * time.Second)
			continue
		}
		mboxMap := make(map[uint32]imap.Message)
		mboxMap, err = updateMessagesMap(log, conf, mboxMap, inboxStatus, c, true)
		if err != nil {
			log.Errorf("%s: update messages error: %v", conf.Label, err)
			_ = c.Logout()
			time.Sleep(5 * time.Second)
			continue
		}
		updates := make(chan client.Update, 128)
		c.Updates = updates
		stopIdle := make(chan struct{})
		doneIdle := make(chan error, 1)
		go func() { doneIdle <- c.Idle(stopIdle, nil) }()
	loop:
		for {
			select {
			case <-ctx.Done():
				close(stopIdle)
				<-doneIdle
				_ = c.Logout()
				return
			case update := <-updates:
				close(stopIdle)
				<-doneIdle
				switch u := update.(type) {
				case *client.MailboxUpdate:
					inboxStatus, err = c.Select(conf.Mailbox, true)
					if err != nil {
						log.Errorf("%s: select after update error: %v", conf.Label, err)
						break loop
					}
					mboxMap, err = updateMessagesMap(log, conf, mboxMap, inboxStatus, c, false)
					if err != nil {
						log.Errorf("%s: updateMessagesMap error: %v", conf.Label, err)
						break loop
					}
				case *client.ExpungeUpdate:
					mboxMap = expunge(log, conf, mboxMap, u.SeqNum)
				}
				stopIdle = make(chan struct{})
				doneIdle = make(chan error, 1)
				go func() { doneIdle <- c.Idle(stopIdle, nil) }()
			case <-time.After(keepAlive):
				close(stopIdle)
				<-doneIdle
				stopIdle = make(chan struct{})
				doneIdle = make(chan error, 1)
				go func() { doneIdle <- c.Idle(stopIdle, nil) }()
			}
		}
		_ = c.Logout()
		time.Sleep(5 * time.Second)
	}
}

// tryPasswordLogin: test di login utente/password.
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

// openBrowser apre l'URL nel browser di sistema (best effort)
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return fmt.Errorf("unsupported platform for auto-open")
	}
}

// Authorization Code Flow con listener locale + PKCE quando client_secret è vuoto
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
		port := ln.Addr().(*net.TCPAddr).Port
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
		_, _ = io.WriteString(w, "Autenticazione completata. Puoi chiudere questa finestra e tornare al terminale.\n")
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
	fmt.Printf("Apri nel browser la seguente URL e concedi l'accesso:\n%s\n", authURL)
	fmt.Printf("Se possibile, verrai reindirizzato a %s\n", redirectURI)
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
		hc := &http.Client{Timeout: 15 * time.Second}
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
			b, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(b))
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
			store[cacheKey] = tr.RefreshToken // rimuovi eventuale legacy key
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
	case <-time.After(5 * time.Minute):
		_ = server.Close()
		return fmt.Errorf("timeout waiting for authorization code")
	}
}

// Device Code Flow generico (MS v2: /devicecode)
func runOAuth2DeviceFlow(log *zap.SugaredLogger, conf ProviderConfiguration) error {
	if conf.OAuth2 == nil {
		return fmt.Errorf("no oauth2 configuration")
	}
	oauth := conf.OAuth2
	if oauth.ClientID == "" || oauth.TokenURL == "" || oauth.DeviceCodeURL == "" {
		return fmt.Errorf("device flow requires client_id, token_url, device_code_url")
	}
	form := url.Values{}
	form.Set("client_id", oauth.ClientID)
	if len(oauth.Scope) > 0 {
		form.Set("scope", strings.Join(oauth.Scope, " "))
	}
	req, _ := http.NewRequest("POST", oauth.DeviceCodeURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hc := &http.Client{Timeout: 15 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Errorf("Error closing response body: %s", err)
		}
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("device code endpoint returned %d: %s", resp.StatusCode, string(b))
	}
	var dc struct {
		DeviceCode, UserCode, VerificationURI, VerificationURIComplete string
		ExpiresIn, Interval                                            int
	}
	if err := json.NewDecoder(resp.Body).Decode(&dc); err != nil {
		return err
	}
	if dc.Interval <= 0 {
		dc.Interval = 5
	}
	fmt.Printf("Visita questa pagina e inserisci il codice:\n%s\nCodice: %s\n", dc.VerificationURI, dc.UserCode)
	if dc.VerificationURIComplete != "" {
		fmt.Printf("Oppure apri direttamente:\n%s\n", dc.VerificationURIComplete)
	}
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		form := url.Values{}
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		form.Set("device_code", dc.DeviceCode)
		form.Set("client_id", oauth.ClientID)
		req, _ := http.NewRequest("POST", oauth.TokenURL, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode == 200 {
			var tr struct {
				AccessToken, RefreshToken string
				ExpiresIn                 int64
			}
			if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
				_ = resp.Body.Close()
				return err
			}
			_ = resp.Body.Close()
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
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if strings.Contains(string(b), "authorization_pending") {
			time.Sleep(time.Duration(dc.Interval) * time.Second)
			continue
		}
		if strings.Contains(string(b), "slow_down") {
			dc.Interval += 5
			time.Sleep(time.Duration(dc.Interval) * time.Second)
			continue
		}
		return fmt.Errorf("device flow failed: %s", string(b))
	}
	return fmt.Errorf("device code expired before authorization")
}

func main() {
	config := zap.NewDevelopmentConfig()
	level := zap.NewAtomicLevel()
	level.SetLevel(zap.InfoLevel)
	config.Level = level
	logger, _ := config.Build()
	defer func() {
		if err := logger.Sync(); err != nil {
			fmt.Fprintf(os.Stderr, "Error syncing logger: %s\n", err)
		}
	}()
	log := logger.Sugar()
	var configuration Configuration
	var confFile string
	var debug bool
	var doLogin bool
	var doLoginDevice bool
	var openAuthURL bool
	var imapTrace bool
	var debugTokens bool
	flag.StringVar(&confFile, "c", "config.yaml", "Configuration file")
	flag.StringVar(&confFile, "configuration", "config.yaml", "Configuration file")
	flag.BoolVar(&debug, "d", false, "Debug mode")
	flag.BoolVar(&doLogin, "login", false, "Esegui login interattivo (authorization code) per tutti i provider e esci")
	flag.BoolVar(&doLoginDevice, "login-device", false, "Esegui login interattivo (device code flow) per tutti i provider e esci")
	flag.BoolVar(&openAuthURL, "open-browser", false, "Prova ad aprire automaticamente il browser durante il login")
	flag.BoolVar(&imapTrace, "imap-trace", false, "Stampa il dialogo IMAP (token redatti)")
	flag.BoolVar(&debugTokens, "debug-tokens", false, "Logga aud/scp dei JWT ottenuti")
	flag.Parse()
	if debug {
		level.SetLevel(zap.DebugLevel)
	}
	globalIMAPTrace = imapTrace
	globalDebugTokens = debugTokens
	log.Infof("Starting %s", appName)
	data, err := os.ReadFile(confFile)
	if err != nil {
		log.Fatalf("Error reading configuration file: %s", err)
	}
	if err = yaml.Unmarshal(data, &configuration); err != nil {
		log.Fatalf("Error parsing configuration file: %s", err)
	}
	if doLogin || doLoginDevice {
		for _, conf := range configuration.Providers {
			if conf.OAuth2 != nil {
				if doLoginDevice {
					log.Infof("%s: avvio device code flow...", conf.Label)
					if err := runOAuth2DeviceFlow(log, conf); err != nil {
						log.Errorf("%s: device code login failed: %v", conf.Label, err)
					} else {
						log.Infof("%s: device code login completed", conf.Label)
					}
				} else {
					log.Infof("%s: avvio authorization code flow...", conf.Label)
					if err := runOAuth2Flow(log, conf, openAuthURL); err != nil {
						log.Errorf("%s: OAuth2 login failed: %v", conf.Label, err)
					} else {
						log.Infof("%s: OAuth2 login completed", conf.Label)
					}
				}
			} else {
				log.Infof("%s: test login username/password...", conf.Label)
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
		go func(c ProviderConfiguration) { defer wg.Done(); runIMAPClient(ctx, log, c) }(conf)
	}
	wg.Wait()
}
