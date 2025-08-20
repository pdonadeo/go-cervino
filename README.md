# go-cervino

Dead simple IMAP desktop notification daemon that Just Works™!

go-cervino is an IMAP inbox watcher for Linux desktops. It connects to one or more IMAP servers, listens for new mail
via IDLE, and shows desktop notifications (libnotify/DBus). Supports both username/password and OAuth2 (XOAUTH2)
authentication.

- Desktop notifications with optional icon, sound, and timeout
- Read-only IMAP access (does not mark messages as seen)
- OAuth2 Authorization Code flow with localhost redirect (PKCE when no client secret)
- Caches refresh tokens on disk and access tokens in memory

## Requirements

- Linux desktop with a notification daemon (e.g., dunst, notify-osd) and a DBus session
- Go toolchain to build from source

## Build

From the project root:

```bash
go build -o go-cervino .
```

Run:

```bash
./go-cervino -c config.yaml
```

Optional flags:

- -d: enable debug logs
- --login: run interactive OAuth2 login for all providers in the config, then exit
- --open-browser: attempt to auto-open the auth URL during --login
- --imap-trace: print the IMAP conversation (for debugging)

## Configuration

Create a YAML file (default path: config.yaml). Example with Gmail (OAuth2) and a generic IMAP server (password):

```yaml
providers:
  - label: Personal Gmail
    host: imap.gmail.com
    port: 993
    username: your.name@gmail.com
    mailbox: INBOX
    icon: mail-unread
    sound: /usr/share/sounds/freedesktop/stereo/message.oga
    timeout: 10
    oauth2:
      client_id: "YOUR_GOOGLE_OAUTH_CLIENT_ID"
      # When client_secret is empty, PKCE is used (recommended for desktop apps).
      client_secret: ""
      auth_url: "https://accounts.google.com/o/oauth2/v2/auth"
      token_url: "https://oauth2.googleapis.com/token"
      # Optional. If omitted, a random localhost port is used.
      redirect_uri: "http://127.0.0.1:7777/callback"
      scope:
        - "https://mail.google.com/"

  - label: Work IMAP (password)
    host: imap.example.com
    port: 993
    username: your.name@example.com
    password: "set-from-env-or-secret-manager"
    mailbox: INBOX
    timeout: 10
```

Field reference:

- label: name shown in logs/notifications
- host/port: IMAP server (TLS on 993 is expected)
- username/password: for password auth (omit password when using OAuth2)
- mailbox: IMAP mailbox to watch (default INBOX)
- icon: notification icon name/path
- sound: path to a sound file to play in the notification
- timeout: notification timeout in seconds (0 = never expire)
- oauth2: OAuth2 settings (when present, XOAUTH2 is used)

OAuth2 block:

- client_id: OAuth Client ID
- client_secret: optional; if empty, PKCE is used
- auth_url: Authorization endpoint
- token_url: Token endpoint
- redirect_uri: optional localhost redirect; if omitted, a random port is used
- scope: list of scopes required for IMAP

## OAuth2 quick start

1. Add your provider block with oauth2 in config.yaml (as above).

2. Run the login flow:

```bash
./go-cervino --login --open-browser -c config.yaml
```

3. Complete consent in the browser. On success, the app will store your refresh token at:

- $XDG_CONFIG_HOME/go-cervino/oauth_tokens.json
- or ~/.config/go-cervino/oauth_tokens.json

Access tokens are cached in memory and refreshed automatically.

### Provider notes

- Google (Gmail)
  - auth_url: https://accounts.google.com/o/oauth2/v2/auth
  - token_url: https://oauth2.googleapis.com/token
  - scope: ["https://mail.google.com/"]
  - Create an OAuth client (Desktop app) in Google Cloud Console.

- Microsoft 365 / Outlook
  - auth_url: https://login.microsoftonline.com/common/oauth2/v2.0/authorize
  - token_url: https://login.microsoftonline.com/common/oauth2/v2.0/token
  - scope: ["offline_access", "https://outlook.office365.com/IMAP.AccessAsUser.All"]
  - Configure a public client (mobile/desktop) in Azure AD; enable IMAP permissions and
    grant admin consent when required.

## Usage

Typical run:

```bash
./go-cervino -c config.yaml
```

Debugging and tracing:

```bash
./go-cervino -c config.yaml -d --imap-trace
```

Notes:

- The app selects the mailbox in read-only mode and never alters flags.
- On startup it records the current unseen UIDs to avoid retroactive notifications.
- Notifications are sent once per new message UID per session.

## Systemd service (optional)

Create /etc/systemd/system/go-cervino.service:

```ini
[Unit]
Description=go-cervino IMAP notifier
After=network-online.target

[Service]
Type=simple
ExecStart=%h/.local/bin/go-cervino -d -c %h/.config/go-cervino/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
```

Then:

```bash
mkdir -p ~/.config/go-cervino
cp config.yaml ~/.config/go-cervino/config.yaml
cp go-cervino ~/.local/bin/go-cervino
systemctl --user daemon-reload
systemctl --user enable --now go-cervino
```

DBus access for desktop notifications typically requires running under the user session or configuring
lingering user services.

## Troubleshooting

- No notifications: ensure a notification daemon is running and DBus session is available.
- OAuth errors: use --login with -d and consider --imap-trace to inspect server responses. Do not share logs publicly.
- Authentication failures with OAuth2: verify scopes, tenant configuration, and that IMAP is enabled server-side.
- Password auth: some providers block password login; prefer OAuth2 where available.

## Security

- Refresh tokens are stored in plain JSON under your user config directory. Protect file permissions and the
  machine account.
- Consider using separate provider accounts or limited scopes where possible.
- **Avoid sharing logs collected with --imap-trace as they may include sensitive data:** this means
  don't send logs to public forums or pastebins or a LLM chatbot.
