// pickup-relay drains an SMTP pickup directory: the sidecar of an application that writes mail as .eml files
// (System.Net.Mail SmtpDeliveryMethod.SpecifiedPickupDirectory) where an IIS SMTP service used to send them.
//
// Each *.eml file in PICKUP_DIR is parsed, its envelope taken from the X-Sender / X-Receiver lines that .NET
// and IIS pickup files start with (or else from the From, To, Cc and Bcc headers), and sent to SMTP_HOST:SMTP_PORT,
// with STARTTLS when the relay offers it (required unless SMTP_TLS=none, implicit TLS with SMTP_TLS=implicit)
// and authentication when SMTP_USERNAME is set. A sent file moves to sent/, one the relay refuses for good to
// failed/ with a .error file beside it; a temporary failure (connection refused, 4xx) stays for the next pass.
// Logs go to stdout, one JSON object per line. No shell, no files outside PICKUP_DIR.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type config struct {
	Dir       string
	Host      string
	Port      int
	TLS       string // starttls (default: required), implicit, opportunistic, none
	Username  string
	Password  string
	HeloName  string
	Interval  time.Duration
	Settle    time.Duration // a file younger than this may still be being written
	Timeout   time.Duration
	KeepSent  bool
	Once      bool
	TLSConfig *tls.Config
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func loadConfig() (config, error) {
	c := config{
		Dir:      env("PICKUP_DIR", "/pickup"),
		Host:     env("SMTP_HOST", ""),
		TLS:      strings.ToLower(env("SMTP_TLS", "starttls")),
		Username: env("SMTP_USERNAME", ""),
		Password: env("SMTP_PASSWORD", ""),
		HeloName: env("SMTP_HELO", "pickup-relay"),
		KeepSent: env("KEEP_SENT", "true") != "false",
		Once:     env("ONCE", "false") == "true",
	}
	port := env("SMTP_PORT", "")
	if port == "" {
		port = "587"
		if c.TLS == "implicit" {
			port = "465"
		} else if c.TLS == "none" {
			port = "25"
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 {
		return c, fmt.Errorf("SMTP_PORT %q is not a port", port)
	}
	c.Port = p
	for _, d := range []struct {
		k   string
		def string
		to  *time.Duration
	}{{"POLL_INTERVAL", "5s", &c.Interval}, {"SETTLE_TIME", "2s", &c.Settle}, {"SMTP_TIMEOUT", "30s", &c.Timeout}} {
		v, err := time.ParseDuration(env(d.k, d.def))
		if err != nil {
			return c, fmt.Errorf("%s: %v", d.k, err)
		}
		*d.to = v
	}
	switch c.TLS {
	case "starttls", "implicit", "opportunistic", "none":
	default:
		return c, fmt.Errorf("SMTP_TLS %q: starttls, implicit, opportunistic or none", c.TLS)
	}
	if c.Host == "" {
		return c, errors.New("SMTP_HOST is not set: the relay does not know where to send mail")
	}
	c.TLSConfig = &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}
	return c, nil
}

func logj(level, msg string, kv ...any) {
	m := map[string]any{"time": time.Now().UTC().Format(time.RFC3339), "level": level, "msg": msg}
	for i := 0; i+1 < len(kv); i += 2 {
		m[fmt.Sprint(kv[i])] = kv[i+1]
	}
	b, _ := json.Marshal(m)
	fmt.Println(string(b))
}

// envelope is a message ready to send: the envelope sender and recipients, and the data without the X-Sender /
// X-Receiver lines and without a Bcc header.
type envelope struct {
	From string
	To   []string
	Data []byte
}

// permanentError is a failure that sending again will not fix: the file goes to failed/.
type permanentError struct{ error }

func parseAddrs(v string) ([]string, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	list, err := mail.ParseAddressList(v)
	if err != nil {
		// a bare address without a display name that net/mail refuses (e.g. local part with odd characters)
		a := strings.Trim(strings.TrimSpace(v), "<>")
		if strings.Count(a, "@") == 1 && !strings.ContainsAny(a, " ,;") {
			return []string{a}, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.Address)
	}
	return out, nil
}

// parse reads a pickup file. .NET (and IIS) write "X-Sender: <addr>" and one "X-Receiver: <addr>" per recipient
// as the first lines; the relay takes the envelope from them and removes them, as the IIS SMTP service did.
func parse(raw []byte) (envelope, error) {
	var e envelope
	// the leading X-Sender / X-Receiver lines
	rest := raw
	for {
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(rest[:i]), "\r")
		name, val, ok := strings.Cut(line, ":")
		if !ok {
			break
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "x-sender":
			a, err := parseAddrs(val)
			if err != nil || len(a) != 1 {
				return e, permanentError{fmt.Errorf("X-Sender %q is not one address", strings.TrimSpace(val))}
			}
			e.From = a[0]
		case "x-receiver":
			a, err := parseAddrs(val)
			if err != nil || len(a) == 0 {
				return e, permanentError{fmt.Errorf("X-Receiver %q is not an address", strings.TrimSpace(val))}
			}
			e.To = append(e.To, a...)
		default:
			goto headers
		}
		rest = rest[i+1:]
	}
headers:
	msg, err := mail.ReadMessage(bytes.NewReader(rest))
	if err != nil {
		return e, permanentError{fmt.Errorf("not a mail message: %v", err)}
	}
	if e.From == "" {
		for _, h := range []string{"Sender", "From"} {
			if a, err := parseAddrs(msg.Header.Get(h)); err == nil && len(a) > 0 {
				e.From = a[0]
				break
			}
		}
	}
	if len(e.To) == 0 {
		for _, h := range []string{"To", "Cc", "Bcc"} {
			for _, v := range msg.Header[h] {
				a, err := parseAddrs(v)
				if err != nil {
					return e, permanentError{fmt.Errorf("%s header: %v", h, err)}
				}
				e.To = append(e.To, a...)
			}
		}
	}
	if e.From == "" {
		return e, permanentError{errors.New("no sender: neither X-Sender nor From")}
	}
	if len(e.To) == 0 {
		return e, permanentError{errors.New("no recipients: neither X-Receiver nor To, Cc or Bcc")}
	}
	e.Data = stripBcc(rest)
	return e, nil
}

// stripBcc removes Bcc header fields (and their folded continuation lines) from the header section.
func stripBcc(b []byte) []byte {
	var out bytes.Buffer
	r := bufio.NewReader(bytes.NewReader(b))
	inHeaders, skipping := true, false
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			if inHeaders {
				t := bytes.TrimRight(line, "\r\n")
				switch {
				case len(t) == 0:
					inHeaders, skipping = false, false
				case t[0] == ' ' || t[0] == '\t':
					// continuation of the previous field
				default:
					name, _, _ := bytes.Cut(t, []byte(":"))
					skipping = strings.EqualFold(strings.TrimSpace(string(name)), "bcc")
				}
				if skipping {
					if err != nil {
						break
					}
					continue
				}
			}
			out.Write(line)
		}
		if err != nil {
			break
		}
	}
	return out.Bytes()
}

// normalizeCRLF makes every line end in CRLF, as SMTP DATA requires.
func normalizeCRLF(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))
}

// temporary tells a failure worth retrying (no connection, a 4xx reply) from one that is not (5xx).
func temporary(err error) bool {
	var pe permanentError
	if errors.As(err, &pe) {
		return false
	}
	var te *textproto.Error
	if errors.As(err, &te) {
		return te.Code < 500
	}
	return true
}

func send(c config, e envelope) error {
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	d := &net.Dialer{Timeout: c.Timeout}
	var conn net.Conn
	var err error
	if c.TLS == "implicit" {
		conn, err = tls.DialWithDialer(d, "tcp", addr, c.TLSConfig)
	} else {
		conn, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(c.Timeout * 4))
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if err = cl.Hello(c.HeloName); err != nil {
		return err
	}
	if c.TLS == "starttls" || c.TLS == "opportunistic" {
		if ok, _ := cl.Extension("STARTTLS"); ok {
			if err = cl.StartTLS(c.TLSConfig); err != nil {
				return err
			}
		} else if c.TLS == "starttls" {
			return errors.New("the relay does not offer STARTTLS (SMTP_TLS=opportunistic or none allows plain text)")
		}
	}
	if c.Username != "" {
		if ok, _ := cl.Extension("AUTH"); !ok {
			return errors.New("SMTP_USERNAME is set but the relay offers no AUTH")
		}
		// net/smtp refuses PLAIN over an unencrypted connection to anything but localhost
		if err = cl.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			return err
		}
	}
	if err = cl.Mail(e.From); err != nil {
		return err
	}
	for _, r := range e.To {
		if err = cl.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err = w.Write(normalizeCRLF(e.Data)); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

func moveTo(c config, path, sub string) (string, error) {
	dir := filepath.Join(c.Dir, sub)
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, filepath.Base(path))
	if _, err := os.Stat(dst); err == nil {
		dst = filepath.Join(dir, strconv.FormatInt(time.Now().UnixNano(), 10)+"-"+filepath.Base(path))
	}
	return dst, os.Rename(path, dst)
}

// pass sends every settled .eml file once; it returns how many were sent, failed and left for later.
func pass(c config) (sent, failed, deferred int) {
	entries, err := os.ReadDir(c.Dir)
	if err != nil {
		logj("error", "cannot read the pickup folder", "dir", c.Dir, "error", err.Error())
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, de := range entries {
		if de.IsDir() || !strings.EqualFold(filepath.Ext(de.Name()), ".eml") {
			continue
		}
		path := filepath.Join(c.Dir, de.Name())
		info, err := de.Info()
		if err != nil || time.Since(info.ModTime()) < c.Settle {
			deferred++
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			deferred++
			continue
		}
		e, err := parse(raw)
		if err == nil {
			err = send(c, e)
		}
		switch {
		case err == nil:
			sent++
			if c.KeepSent {
				_, _ = moveTo(c, path, "sent")
			} else {
				_ = os.Remove(path)
			}
			logj("info", "sent", "file", de.Name(), "from", e.From, "recipients", len(e.To),
				"relay", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)))
		case temporary(err):
			deferred++
			logj("warn", "not sent, will retry", "file", de.Name(), "error", err.Error(),
				"relay", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)))
		default:
			failed++
			dst, merr := moveTo(c, path, "failed")
			if merr == nil {
				_ = os.WriteFile(dst+".error", []byte(err.Error()+"\n"), 0o640)
			}
			logj("error", "failed", "file", de.Name(), "error", err.Error())
		}
	}
	return
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		fmt.Println("pickup-relay: sends the .eml files of PICKUP_DIR to SMTP_HOST:SMTP_PORT (see the image's README)")
		return
	}
	c, err := loadConfig()
	if err != nil {
		logj("error", "configuration", "error", err.Error())
		os.Exit(2)
	}
	logj("info", "watching", "dir", c.Dir, "relay", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)), "tls", c.TLS,
		"auth", c.Username != "")
	for {
		s, f, d := pass(c)
		if c.Once {
			if f > 0 || d > 0 {
				os.Exit(1)
			}
			_ = s
			return
		}
		time.Sleep(c.Interval)
	}
}
