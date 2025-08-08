package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/TheCreeper/go-notify"
	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type ProviderConfiguration struct {
	Label    string
	Host     string
	Port     int
	Username string
	Password string
	Mailbox  string
	Sound    string
	Icon     string
	Timeout  int32
}

type Configuration struct {
	Providers []ProviderConfiguration `yaml:"providers"`
}

var appName = "go-cervino"

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
				ntf := notify.NewNotification(
					"New email in "+conf.Label,
					fmt.Sprintf("<b>%s</b> from <i>%s</i>", msg.Envelope.Subject, msg.Envelope.From[0].PersonalName))
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

func runIMAPClient(ctx context.Context, log *zap.SugaredLogger, conf ProviderConfiguration) {
	keepAlive := 5 * time.Minute

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		log.Debugf("Connecting to \"%s\"...", conf.Label)
		c, err := client.DialTLS(fmt.Sprintf("%s:%d", conf.Host, conf.Port), nil)
		if err != nil {
			log.Error(err)
			time.Sleep(5 * time.Second)
			continue
		}
		log.Debugf("...%s connected", conf.Label)

		if err = c.Login(conf.Username, conf.Password); err != nil {
			log.Errorf("%s: %s", conf.Label, err)
			_ = c.Logout()
			time.Sleep(5 * time.Second)
			continue
		}
		log.Debugf("%s logged in", conf.Label)

		if conf.Mailbox == "" {
			conf.Mailbox = "INBOX"
		}
		inboxStatus, err := c.Select(conf.Mailbox, true)
		if err != nil {
			log.Errorf("%s: %s", conf.Label, err)
			_ = c.Logout()
			time.Sleep(5 * time.Second)
			continue
		}

		mboxMap := make(map[uint32]imap.Message)
		mboxMap, err = updateMessagesMap(log, conf, mboxMap, inboxStatus, c, true)
		if err != nil {
			log.Errorf("%s: %s", conf.Label, err)
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
						log.Errorf("%s: %s", conf.Label, err)
						break loop
					}
					mboxMap, err = updateMessagesMap(log, conf, mboxMap, inboxStatus, c, false)
					if err != nil {
						log.Errorf("%s: %s", conf.Label, err)
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

	flag.StringVar(&confFile, "c", "config.yaml", "Configuration file")
	flag.StringVar(&confFile, "configuration", "config.yaml", "Configuration file")
	flag.BoolVar(&debug, "d", false, "Debug mode")
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
