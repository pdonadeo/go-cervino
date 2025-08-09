package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
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

// OAuth2Config contiene i campi necessari per ottenere access token da refresh token.
// Ho aggiunto AuthURL e (opzionalmente) RedirectURI per gestire il flusso di authorization code.
type OAuth2Config struct {
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	RefreshToken string   `yaml:"refresh_token"`
	TokenURL     string   `yaml:"token_url"`
	AuthURL      string   `yaml:"auth_url"`
	RedirectURI  string   `yaml:"redirect_uri"` // opzionale, se vuoto useremo localhost con porta dinamica
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

type Configuration struct {
	Providers []ProviderConfiguration `yaml:"providers"`
}

var appName = "go-cervino"

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

func loadTokenStore() (map[string]string, error) {
	p := tokenStorePath()
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	defer f.Close()
	m := map[string]string{}
	dec := json.NewDecoder(f)
	if err := dec.Decode(&m); err != nil && err != io.EOF {
		return nil, err
	}
	return m, nil
}

func saveTokenStore(m map[string]string) error {
	p := tokenStorePath()
	d := filepath.Dir(p)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	defer f.Close()
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
	log.Debugf("%s: Mailbox update: %d messages, %d recent, %d unseen, %d unseenSeqNum",
		conf.Label, mboxStatus.Messages, mboxStatus.Recent, mboxStatus.Unseen, mboxStatus.UnseenSeqNum)
}

func updateMessagesMap(
	log *zap.SugaredLogger,
	conf ProviderConfiguration,
	mboxMap map[uint32]imap.Message,
	mboxStatus *imap.MailboxStatus,
	c *client.Client,
	alsoNewMessages bool,
) (map[uint32]imap.Message, error) {
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
	go func() {
		done <- c.Fetch(seqset, []imap.FetchItem{imap.FetchAll}, messages)
	}()

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
				ntf := notify.NewNotification(
					"New email in "+conf.Label,
					fmt.Sprintf("<b>%s</b> from <i>%s</i>", msg.Envelope.Subject, fromName))
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

func expunge(
	log *zap.SugaredLogger,
	conf ProviderConfiguration,
	mboxMap map[uint32]imap.Message,
	seqNum uint32,
) map[uint32]imap.Message {
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

// getAccessTokenFromRefreshToken esegue la chiamata al token endpoint per ottenere un access token
// a partire da un refresh_token. Restituisce anche la scadenza (expires_in).
func getAccessTokenFromRefreshToken(ctx context.Context, oauth *OAuth2Config) (string, time.Time, error) {
	if oauth.TokenURL == "" {
		return "", time.Time{}, fmt.Errorf("token_url non impostato in configurazione OAuth2")
	}

	form := url.Values{}
	form.Set("client_id", oauth.ClientID)
	form.Set("client_secret", oauth.ClientSecret)
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
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return "", time.Time{}, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&tokenResp); err != nil {
		return "", time.Time{}, err
	}

	expiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	if tokenResp.ExpiresIn == 0 {
		expiry = time.Now().Add(1 * time.Hour)
	}

	return tokenResp.AccessToken, expiry, nil
}

// fetchAccessToken usa la cache e rinnova l'access token se necessario.
// cacheKey è composta da token_url|username|label per separare provider diversi.
func fetchAccessToken(ctx context.Context, label string, username string, oauth *OAuth2Config) (string, error) {
	cacheKey := oauth.TokenURL + "|" + username + "|" + label

	// se manca refresh token nella struct, proviamo a caricarlo dallo store su disco
	if oauth.RefreshToken == "" {
		store, err := loadTokenStore()
		if err == nil {
			if v, ok := store[cacheKey]; ok {
				oauth.RefreshToken = v
			}
		}
	}

	tokenCache.Lock()
	item, ok := tokenCache.m[cacheKey]
	tokenCache.Unlock()

	const margin = 60 * time.Second

	if ok && time.Now().Add(margin).Before(item.Expiry) && item.AccessToken != "" {
		return item.AccessToken, nil
	}

	if oauth.RefreshToken == "" {
		return "", fmt.Errorf("no refresh token available for provider %s user %s", label, username)
	}

	accessToken, expiry, err := getAccessTokenFromRefreshToken(ctx, oauth)
	if err != nil {
		return "", err
	}

	tokenCache.Lock()
	tokenCache.m[cacheKey] = tokenCacheItem{
		AccessToken: accessToken,
		Expiry:      expiry,
	}
	tokenCache.Unlock()

	return accessToken, nil
}

// Implementazione minimale di SASL XOAUTH2 come sasl.Client per go-sasl
type xoauth2Client struct {
	username string
	token    string
	started  bool
}

func NewXOAuth2(username, token string) sasl.Client {
	return &xoauth2Client{username: username, token: token}
}

// Start ritorna il meccanismo e la initial response richiesta da XOAUTH2
func (c *xoauth2Client) Start() (string, []byte, error) {
	// Formato: "user=<user>\x01auth=Bearer <accessToken>\x01\x01"
	ir := []byte("user=" + c.username + "\x01auth=Bearer " + c.token + "\x01\x01")
	c.started = true
	return "XOAUTH2", ir, nil
}

// Next non viene usato da XOAUTH2 (nessuna challenge-response prevista)
func (c *xoauth2Client) Next(challenge []byte) ([]byte, error) {
	// Non ci aspettiamo challenge; rispondiamo con nil
	return nil, nil
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
		log.Debugf("...%s connected", conf.Label)

		// Autenticazione: password classica oppure OAuth2 XOAUTH2
		if conf.OAuth2 != nil {
			tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			token, err := fetchAccessToken(tctx, conf.Label, conf.Username, conf.OAuth2)
			cancel()
			if err != nil {
				log.Errorf("%s: cannot get OAuth2 token: %v", conf.Label, err)
				_ = c.Logout()
				time.Sleep(5 * time.Second)
				continue
			}

			auth := NewXOAuth2(conf.Username, token)
			if err := c.Authenticate(auth); err != nil {
				log.Errorf("%s: OAuth2 auth failed: %v", conf.Label, err)
				_ = c.Logout()
				time.Sleep(5 * time.Second)

				// Invalida cache per forzare refresh la prossima volta
				cacheKey := conf.OAuth2.TokenURL + "|" + conf.Username + "|" + conf.Label
				tokenCache.Lock()
				delete(tokenCache.m, cacheKey)
				tokenCache.Unlock()

				continue
			}
		} else {
			if err := c.Login(conf.Username, conf.Password); err != nil {
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

// tryPasswordLogin tenta una connessione IMAP e login con username/password (senza loop)
func tryPasswordLogin(conf ProviderConfiguration) error {
	addr := fmt.Sprintf("%s:%d", conf.Host, conf.Port)
	c, err := client.DialTLS(addr, nil)
	if err != nil {
		return err
	}
	defer c.Logout()
	return c.Login(conf.Username, conf.Password)
}

// runOAuth2Flow esegue un authorization code flow minimale con redirect su localhost:porta dinamica
// stampa la URL da aprire e attende il codice. Salva il refresh_token nello store su disco.
func runOAuth2Flow(conf ProviderConfiguration) error {
	if conf.OAuth2 == nil {
		return fmt.Errorf("no oauth2 configuration")
	}
	oauth := conf.OAuth2
	if oauth.ClientID == "" || oauth.ClientSecret == "" || oauth.AuthURL == "" || oauth.TokenURL == "" {
		return fmt.Errorf("oauth2 configuration incomplete: client_id, client_secret, auth_url and token_url are required")
	}

	// apriamo listener su porta libera
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("cannot open listener: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	redirectURI := oauth.RedirectURI
	if redirectURI == "" {
		redirectURI = fmt.Sprintf("http://localhost:%d/callback", port)
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", oauth.ClientID)
	q.Set("redirect_uri", redirectURI)
	if oauth.Scope != nil && len(oauth.Scope) > 0 {
		q.Set("scope", strings.Join(oauth.Scope, " "))
	}
	// alcuni provider richiedono parametri aggiuntivi per ottenere refresh token
	q.Set("access_type", "offline")
	q.Set("prompt", "consent")

	authURL := oauth.AuthURL + "?" + q.Encode()

	fmt.Printf("Apri nel browser la seguente URL e concedi l'accesso:\n%s\n", authURL)
	fmt.Printf("Se possibile, verrai reindirizzato a %s\n", redirectURI)

	codeCh := make(chan string)
	errCh := make(chan error)

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		vals := r.URL.Query()
		if err := vals.Get("error"); err != "" {
			http.Error(w, "authorization error: "+err, http.StatusBadRequest)
			select {
			case errCh <- fmt.Errorf("authorization error: %s", err):
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
		io.WriteString(w, "Autenticazione completata. Puoi chiudere questa finestra e tornare al terminale.\n")
		select {
		case codeCh <- code:
		default:
		}
	})

	server := &http.Server{}
	go func() {
		// serve using existing listener (so we don't conflict with other services)
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			select {
			case errCh <- err:
			default:
			}
		}
	}()

	// aspettiamo codice o errore con timeout
	select {
	case code := <-codeCh:
		// prosegui
		_ = server.Shutdown(context.Background())
		// scambiamo il codice per token
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", redirectURI)
		form.Set("client_id", oauth.ClientID)
		form.Set("client_secret", oauth.ClientSecret)

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
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			b, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(b))
		}

		var tr struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int64  `json:"expires_in"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
			return err
		}

		if tr.RefreshToken == "" {
			fmt.Printf("Attenzione: il token endpoint non ha restituito refresh_token. Potrebbe essere necessario richiedere scope aggiuntivi (es. offline_access) o prompt/consent speciali.\n")
		}

		// salva refresh token nello store su disco
		cacheKey := oauth.TokenURL + "|" + conf.Username + "|" + conf.Label
		store, err := loadTokenStore()
		if err != nil {
			return err
		}
		if tr.RefreshToken != "" {
			store[cacheKey] = tr.RefreshToken
			if err := saveTokenStore(store); err != nil {
				return err
			}
			fmt.Printf("Refresh token salvato nello store (%s).\n", tokenStorePath())
		} else if oauth.RefreshToken != "" {
			// niente da fare, già presente nella config
			fmt.Printf("Refresh token presente nella configurazione iniziale; nessuna modifica effettuata.\n")
		} else {
			fmt.Printf("Nessun refresh token disponibile per il salvataggio.\n")
		}

		// memorizziamo anche nella struct in memoria per coerenza
		if tr.RefreshToken != "" {
			oauth.RefreshToken = tr.RefreshToken
		}

		_ = resp.Body.Close()
		_ = server.Close()
		return nil

	case err := <-errCh:
		_ = server.Close()
		return err
	case <-time.After(5 * time.Minute):
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
		if err := logger.Sync(); err != nil {
			fmt.Fprintf(os.Stderr, "Error syncing logger: %s\n", err)
		}
	}()

	log := logger.Sugar()

	var configuration Configuration
	var confFile string
	var debug bool
	var doLogin bool

	flag.StringVar(&confFile, "c", "config.yaml", "Configuration file")
	flag.StringVar(&confFile, "configuration", "config.yaml", "Configuration file")
	flag.BoolVar(&debug, "d", false, "Debug mode")
	flag.BoolVar(&doLogin, "login", false, "Esegui login interattivo per tutti i provider e esci")
	flag.Parse()

	if debug {
		level.SetLevel(zap.DebugLevel)
	}

	log.Infof("Starting %s", appName)

	data, err := os.ReadFile(confFile)
	if err != nil {
		log.Fatalf("Error reading configuration file: %s", err)
	}

	if err = yaml.Unmarshal(data, &configuration); err != nil {
		log.Fatalf("Error parsing configuration file: %s", err)
	}

	if doLogin {
		// Esegui login test / oauth flow per ogni provider e poi esci
		for _, conf := range configuration.Providers {
			if conf.OAuth2 != nil {
				log.Infof("%s: avvio flusso OAuth2...", conf.Label)
				if err := runOAuth2Flow(conf); err != nil {
					log.Errorf("%s: OAuth2 login failed: %v", conf.Label, err)
				} else {
					log.Infof("%s: OAuth2 login completed", conf.Label)
				}
			} else {
				log.Infof("%s: test login username/password...", conf.Label)
				if err := tryPasswordLogin(conf); err != nil {
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
			runIMAPClient(ctx, log, c)
		}(conf)
	}

	wg.Wait()
}
