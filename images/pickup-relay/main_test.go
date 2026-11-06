package main

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// what System.Net.Mail writes into a pickup folder (SmtpDeliveryMethod.SpecifiedPickupDirectory)
const dotnetEml = "X-Sender: noreply@lucernebank.example\r\n" +
	"X-Receiver: alice@example.com\r\n" +
	"X-Receiver: bob@example.com\r\n" +
	"MIME-Version: 1.0\r\n" +
	"From: Lucerne Savings Bank <noreply@lucernebank.example>\r\n" +
	"To: alice@example.com\r\n" +
	"Bcc: bob@example.com\r\n" +
	"Date: 6 Nov 2026 01:00:00 +0000\r\n" +
	"Subject: Your agreement\r\n" +
	"Content-Type: text/plain; charset=us-ascii\r\n" +
	"Content-Transfer-Encoding: quoted-printable\r\n" +
	"\r\n" +
	"Hello\r\n"

func TestParseDotnetPickupFile(t *testing.T) {
	e, err := parse([]byte(dotnetEml))
	if err != nil {
		t.Fatal(err)
	}
	if e.From != "noreply@lucernebank.example" || strings.Join(e.To, ",") != "alice@example.com,bob@example.com" {
		t.Fatalf("envelope %q %q", e.From, e.To)
	}
	d := string(e.Data)
	if strings.Contains(d, "X-Sender") || strings.Contains(d, "X-Receiver") || strings.Contains(d, "Bcc:") {
		t.Fatalf("envelope lines or Bcc left in the data:\n%s", d)
	}
	if !strings.HasPrefix(d, "MIME-Version: 1.0") || !strings.Contains(d, "\r\n\r\nHello") {
		t.Fatalf("data:\n%s", d)
	}
}

func TestParseHeadersOnly(t *testing.T) {
	raw := "From: a@example.com\nTo: B <b@example.com>, c@example.com\nCc: d@example.com\nBcc: e@example.com,\n f@example.com\nSubject: x\n\nbody\n"
	e, err := parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if e.From != "a@example.com" || strings.Join(e.To, ",") != "b@example.com,c@example.com,d@example.com,e@example.com,f@example.com" {
		t.Fatalf("envelope %q %q", e.From, e.To)
	}
	if strings.Contains(string(e.Data), "f@example.com") {
		t.Fatalf("folded Bcc left: %s", e.Data)
	}
}

func TestParseRefusesNoRecipients(t *testing.T) {
	_, err := parse([]byte("From: a@example.com\nSubject: x\n\nbody\n"))
	if err == nil || temporary(err) {
		t.Fatalf("want a permanent error, got %v", err)
	}
}

func TestNormalizeCRLF(t *testing.T) {
	if got := string(normalizeCRLF([]byte("a\nb\r\nc\n"))); got != "a\r\nb\r\nc\r\n" {
		t.Fatalf("%q", got)
	}
}

// a minimal SMTP server: records the envelope and data of each message; rcptCode answers RCPT TO
type fakeSMTP struct {
	ln       net.Listener
	rcptCode string
	got      chan envelope
}

func newFake(t *testing.T, rcptCode string) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, rcptCode: rcptCode, got: make(chan envelope, 10)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := func(s string) { c.Write([]byte(s + "\r\n")) }
	w("220 fake ESMTP")
	var e envelope
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			w("250-fake")
			w("250 8BITMIME")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			e.From = angle(line)
			w("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			e.To = append(e.To, angle(line))
			w(f.rcptCode + " rcpt")
		case cmd == "DATA":
			w("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			e.Data = []byte(b.String())
			f.got <- e
			w("250 queued")
		case cmd == "QUIT":
			w("221 bye")
			return
		default:
			w("250 ok")
		}
	}
}

func testConfig(t *testing.T, addr string) config {
	host, port, _ := net.SplitHostPort(addr)
	t.Setenv("PICKUP_DIR", t.TempDir())
	t.Setenv("SMTP_HOST", host)
	t.Setenv("SMTP_PORT", port)
	t.Setenv("SMTP_TLS", "none")
	t.Setenv("SETTLE_TIME", "0s")
	t.Setenv("SMTP_TIMEOUT", "5s")
	c, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPassSendsAndMoves(t *testing.T) {
	f := newFake(t, "250")
	c := testConfig(t, f.ln.Addr().String())
	if err := os.WriteFile(filepath.Join(c.Dir, "a.eml"), []byte(dotnetEml), 0o644); err != nil {
		t.Fatal(err)
	}
	sent, failed, deferred := pass(c)
	if sent != 1 || failed != 0 || deferred != 0 {
		t.Fatalf("sent %d failed %d deferred %d", sent, failed, deferred)
	}
	select {
	case e := <-f.got:
		if e.From != "noreply@lucernebank.example" || len(e.To) != 2 || !strings.Contains(string(e.Data), "Subject: Your agreement") {
			t.Fatalf("server got %+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing delivered")
	}
	if _, err := os.Stat(filepath.Join(c.Dir, "sent", "a.eml")); err != nil {
		t.Fatal("not moved to sent/")
	}
}

func TestPassPermanentFailure(t *testing.T) {
	f := newFake(t, "550")
	c := testConfig(t, f.ln.Addr().String())
	os.WriteFile(filepath.Join(c.Dir, "b.eml"), []byte(dotnetEml), 0o644)
	if _, failed, _ := pass(c); failed != 1 {
		t.Fatal("want failed")
	}
	msg, err := os.ReadFile(filepath.Join(c.Dir, "failed", "b.eml.error"))
	if err != nil || !strings.Contains(string(msg), "550") {
		t.Fatalf("error file: %q %v", msg, err)
	}
}

func TestPassTemporaryFailureStays(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // connection refused
	c := testConfig(t, addr)
	os.WriteFile(filepath.Join(c.Dir, "c.eml"), []byte(dotnetEml), 0o644)
	if _, _, deferred := pass(c); deferred != 1 {
		t.Fatal("want deferred")
	}
	if _, err := os.Stat(filepath.Join(c.Dir, "c.eml")); err != nil {
		t.Fatal("the file must stay for the next pass")
	}
}

func TestStartTLSRequired(t *testing.T) {
	f := newFake(t, "250")
	c := testConfig(t, f.ln.Addr().String())
	c.TLS = "starttls"
	err := send(c, envelope{From: "a@example.com", To: []string{"b@example.com"}, Data: []byte("Subject: x\r\n\r\nx\r\n")})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("want a STARTTLS refusal, got %v", err)
	}
}

func TestConfigNeedsHost(t *testing.T) {
	t.Setenv("SMTP_HOST", "")
	if _, err := loadConfig(); err == nil {
		t.Fatal("want an error without SMTP_HOST")
	}
}

func angle(line string) string {
	a := strings.Index(line, "<")
	b := strings.Index(line, ">")
	if a < 0 || b < a {
		return ""
	}
	return line[a+1 : b]
}
