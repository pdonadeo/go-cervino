package main

import (
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

var UnlockDelay = 1 * time.Second

var AppName = "go-cervino"

func keys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func PrintMessage(log *zap.SugaredLogger, conf ProviderConfiguration, msg imap.Message) {
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

func PrintMessages(log *zap.SugaredLogger, conf ProviderConfiguration, messages map[uint32]imap.Message) {
	keys := keys(messages)
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		msg := messages[k]
		PrintMessage(log, conf, msg)
	}
}

func PrintMailboxStatus(log *zap.SugaredLogger, msg string, conf ProviderConfiguration, mboxStatus *imap.MailboxStatus) {
	log.Debugf("%s: %s", conf.Label, msg)
	log.Debugf("%s: Mailbox update: %d messages, %d recent, %d unseen, %d unseenSeqNum",
		conf.Label, mboxStatus.Messages, mboxStatus.Recent, mboxStatus.Unseen, mboxStatus.UnseenSeqNum)
}

func UpdateMessagesMap(log *zap.SugaredLogger, conf ProviderConfiguration,
	mboxMap map[uint32]imap.Message,
	mboxStatus *imap.MailboxStatus,
	c *client.Client,
	alsoNewMessages bool) (map[uint32]imap.Message, error) {

	PrintMailboxStatus(log, "UpdateMessageMap", conf, mboxStatus)
	if mboxStatus.Messages == 0 {
		log.Debugf("%s: UpdateMessageMap: mboxStatus.Messages == 0", conf.Label)
		return mboxMap, nil
	}
	from := uint32(0)
	if alsoNewMessages {
		from = 1
	} else {
		if mboxStatus.UnseenSeqNum == 0 {
			from = 1
		} else {
			from = mboxStatus.UnseenSeqNum
		}
	}
	log.Debugf("%s: UpdateMessageMap: from = %d", conf.Label, from)
	to := mboxStatus.Messages
	log.Debugf("%s: UpdateMessageMap: to = %d", conf.Label, to)

	seqset := new(imap.SeqSet)
	seqset.AddRange(from, to)

	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)
	go func() {
		done <- c.Fetch(seqset, []imap.FetchItem{imap.FetchAll}, messages)
	}()

	for msg := range messages {
		_, exists := mboxMap[msg.SeqNum]
		if !exists {
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
				ntf.AppName = AppName
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
				ntf.Show()
			}
		}
	}

	if err := <-done; err != nil {
		return nil, err
	}

	PrintMessages(log, conf, mboxMap)

	return mboxMap, nil
}

func Expunge(
	log *zap.SugaredLogger,
	conf ProviderConfiguration,
	mboxMap map[uint32]imap.Message,
	c *client.Client,
	seqNum uint32) map[uint32]imap.Message {

	keys := keys(mboxMap)
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	newMboxMap := make(map[uint32]imap.Message)
	newSeqNum := uint32(1)
	for _, k := range keys {
		msg := mboxMap[k]
		if msg.SeqNum != seqNum {
			msg.SeqNum = newSeqNum
			newMboxMap[newSeqNum] = msg
			newSeqNum++
		}
	}

	PrintMessages(log, conf, newMboxMap)

	return newMboxMap
}

func RunIMAPClient(log *zap.SugaredLogger, conf ProviderConfiguration, wg *sync.WaitGroup, stopChannel chan bool) {
	keepAliveTicker := time.NewTicker(5 * time.Minute)

	log.Debugf("Connecting to \"%s\"...", conf.Label)

	// Connect to server
	host_port := fmt.Sprintf("%s:%d", conf.Host, conf.Port)
	c, err := client.DialTLS(host_port, nil)
	if err != nil {
		log.Error(err)
		wg.Done()
		return
	}
	log.Debugf("...%s connected", conf.Label)

	if log.Level() == zap.DebugLevel {
		c.SetDebug(os.Stdout)
	}

	if err := c.Login(conf.Username, conf.Password); err != nil {
		log.Errorf("%s: %s", conf.Label, err)
		wg.Done()
		return
	}
	log.Debugf("%s logged in", conf.Label)

	if conf.Mailbox == "" {
		conf.Mailbox = "INBOX"
	}

	inboxStatus, err := c.Select(conf.Mailbox, false)
	if err != nil {
		log.Errorf("%s: %s", conf.Label, err)
		wg.Done()
		return
	}

	mboxMap := make(map[uint32]imap.Message)
	mboxMap, err = UpdateMessagesMap(log, conf, mboxMap, inboxStatus, c, true)
	if err != nil {
		log.Errorf("%s: %s", conf.Label, err)
		wg.Done()
		return
	}

	done := make(chan error, 1)
	// Create a channel to receive mailbox updates
	updates := make(chan client.Update, 128)
	c.Updates = updates

	stop := make(chan struct{})
	stopIsClosed := false

	defer func() {
		log.Infof("%s: Logout", conf.Label)
		if !stopIsClosed {
			close(stop)
			stopIsClosed = true
		}
		err := <-done
		if err != nil {
			log.Errorf("%s: %s", conf.Label, err)
		}
		c.Logout()
		wg.Done()
	}()

	go func() { done <- c.Idle(stop, nil) }()

	for {
		select {
		case update := <-updates:
			log.Debugf("%s: endless loop: updates", conf.Label)
			close(stop)
			stopIsClosed = true

			err = <-done
			if err != nil {
				log.Errorf("%s: an error occurred: %s", conf.Label, err)
				log.Infof("%s: sleeping 5 seconds and restarting IMAP client", conf.Label)
				time.Sleep(5 * time.Second)
				go RunIMAPClient(log, conf, wg, stopChannel)
				return
			}

			switch update := update.(type) {
			case *client.MailboxUpdate:
				close(updates)
				c.Updates = nil

				inboxStatus, err := c.Select(conf.Mailbox, false)
				if err != nil {
					log.Errorf("%s: an error occurred: %s", conf.Label, err)
					log.Infof("%s: sleeping 5 seconds and restarting IMAP client", conf.Label)
					time.Sleep(5 * time.Second)
					go RunIMAPClient(log, conf, wg, stopChannel)
					return
				}
				updates = make(chan client.Update, 128)
				c.Updates = updates

				mboxMap, err = UpdateMessagesMap(log, conf, mboxMap, inboxStatus, c, false)
				if err != nil {
					log.Errorf("%s: an error occurred: %s", conf.Label, err)
					log.Infof("%s: sleeping 5 seconds and restarting IMAP client", conf.Label)
					time.Sleep(5 * time.Second)
					go RunIMAPClient(log, conf, wg, stopChannel)
					return
				}

			case *client.ExpungeUpdate:
				mboxMap = Expunge(log, conf, mboxMap, c, update.SeqNum)
			}
			stop = make(chan struct{})
			stopIsClosed = false
			go func() { done <- c.Idle(stop, nil) }()

		case <-stopChannel:
			log.Debugf("%s: endless loop: <-stopChannel", conf.Label)
			return

		case <-keepAliveTicker.C:
			log.Debugf("%s: endless loop: <-keepAliveTicker.C", conf.Label)
			close(stop)
			stopIsClosed = true

			err = <-done
			if err != nil {
				log.Errorf("%s: an error occurred: %s", conf.Label, err)
				log.Infof("%s: sleeping 5 seconds and restarting IMAP client", conf.Label)
				time.Sleep(5 * time.Second)
				go RunIMAPClient(log, conf, wg, stopChannel)
				return
			}
			stop = make(chan struct{})
			stopIsClosed = false
			go func() { done <- c.Idle(stop, nil) }()
		}
	}
}

func main() {
	config := zap.NewDevelopmentConfig()
	level := zap.NewAtomicLevel()
	level.SetLevel(zap.InfoLevel)
	config.Level = level
	logger, _ := config.Build()
	defer logger.Sync()
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

	log.Infof("Starting %s", AppName)

	data, err := os.ReadFile(confFile)
	if err != nil {
		log.Fatalf("Error reading configuration file: %s", err)
	}

	err = yaml.Unmarshal([]byte(data), &configuration)
	if err != nil {
		log.Fatalf("Error reading configuration file: %s", err)
	}

	var wg sync.WaitGroup
	var signalChannel = make(chan os.Signal, 1)

	var stopChannels = make([]chan bool, len(configuration.Providers))

	for idx, conf := range configuration.Providers {
		stop := make(chan bool, 1)
		stopChannels[idx] = stop
		wg.Add(1)
		go RunIMAPClient(log, conf, &wg, stop)
	}

	wg.Add(1)
	go func() {
		s := <-signalChannel
		log.Infof("Signal %s received", s.String())
		for _, stop := range stopChannels {
			stop <- true
		}
		wg.Done()
	}()
	signal.Notify(signalChannel, syscall.SIGTERM)
	signal.Notify(signalChannel, syscall.SIGINT)

	wg.Wait()
}
