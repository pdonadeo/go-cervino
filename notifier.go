package main

import (
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"
)

type Notifier struct {
	conn      *dbus.Conn
	mu        sync.Mutex
	callbacks map[uint32]func(action string)
	nextID    uint32
}

func NewNotifier() (*Notifier, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to session bus: %w", err)
	}
	n := &Notifier{
		conn:      conn,
		callbacks: make(map[uint32]func(action string)),
		nextID:    1,
	}
	go n.listenActions()
	return n, nil
}

func (n *Notifier) listenActions() {
	_ = n.conn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.Notifications"),
		dbus.WithMatchMember("ActionInvoked"),
	)
	ch := make(chan *dbus.Signal, 10)
	n.conn.Signal(ch)
	for sig := range ch {
		if len(sig.Body) != 2 {
			continue
		}
		id, ok := sig.Body[0].(uint32)
		action, ok2 := sig.Body[1].(string)
		if !ok || !ok2 {
			continue
		}
		n.mu.Lock()
		cb, exists := n.callbacks[id]
		n.mu.Unlock()
		if exists && cb != nil {
			go cb(action)
		}
	}
}

// ShowNotification sends a notification with actions.
// Returns the notification ID.
func (n *Notifier) ShowNotification(summary, body, icon string, actions []string, timeout int32, onAction func(action string)) (uint32, error) {
	n.mu.Lock()
	n.nextID++
	n.mu.Unlock()

	obj := n.conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	var notifID uint32
	call := obj.Call("org.freedesktop.Notifications.Notify", 0,
		"go-cervino",              // app_name
		uint32(0),                 // replaces_id
		icon,                      // app_icon
		summary,                   // summary
		body,                      // body
		actions,                   // actions
		map[string]dbus.Variant{}, // hints
		timeout,                   // expire_timeout (ms)
	)
	if call.Err != nil {
		return 0, call.Err
	}
	if err := call.Store(&notifID); err != nil {
		return 0, err
	}

	if onAction != nil {
		n.mu.Lock()
		n.callbacks[notifID] = onAction
		n.mu.Unlock()
	}

	return notifID, nil
}

// CloseNotification closes a notification by ID.
func (n *Notifier) CloseNotification(id uint32) error {
	obj := n.conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	call := obj.Call("org.freedesktop.Notifications.CloseNotification", 0, id)
	return call.Err
}
