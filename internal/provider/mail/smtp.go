package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"text/template"
	"time"
)

//go:embed templates/*.txt
var templateFS embed.FS

var otpTemplates = func() *template.Template {
	t := template.New("otp")
	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		panic("mail: read embedded templates: " + err.Error())
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "otp_") {
			continue
		}
		data, err := templateFS.ReadFile("templates/" + e.Name())
		if err != nil {
			panic("mail: read template " + e.Name() + ": " + err.Error())
		}
		if _, err := t.New(e.Name()).Parse(string(data)); err != nil {
			panic("mail: parse template " + e.Name() + ": " + err.Error())
		}
	}
	return t
}()

// SMTPConfig holds the configuration for the SMTP mailer.
type SMTPConfig struct {
	Host        string
	Port        int
	User        string
	Password    string
	FromAddress string
	FromName    string
	Timeout     time.Duration
}

type smtpMailer struct {
	cfg    SMTPConfig
	logger *slog.Logger
}

// NewSMTPMailer returns a Mailer backed by an SMTP server using implicit TLS (port 465).
func NewSMTPMailer(cfg SMTPConfig, logger *slog.Logger) (Mailer, error) {
	if logger == nil {
		return nil, fmt.Errorf("nil logger")
	}
	return &smtpMailer{cfg: cfg, logger: logger}, nil
}

// RenderOTPMessage renders an OTP email template for the given locale, returning
// the subject and body separately. Exported for testing.
func RenderOTPMessage(locale Locale, code string, purpose Purpose) (subject, body string, err error) {
	name := "otp_" + string(locale) + ".txt"
	t := otpTemplates.Lookup(name)
	if t == nil {
		t = otpTemplates.Lookup("otp_zh-CN.txt")
		if t == nil {
			return "", "", fmt.Errorf("zh-CN template missing")
		}
	}
	var buf bytes.Buffer
	data := struct {
		Code    string
		Purpose string
	}{Code: code, Purpose: string(purpose)}
	if err := t.Execute(&buf, data); err != nil {
		return "", "", err
	}
	rendered := buf.String()
	rendered = strings.TrimPrefix(rendered, "\xef\xbb\xbf") // strip BOM if present
	if !strings.HasPrefix(rendered, "Subject:") {
		return "", "", fmt.Errorf("template %s does not start with Subject:", name)
	}
	idx := strings.Index(rendered, "\n")
	if idx < 0 {
		return "", "", fmt.Errorf("template %s missing newline after Subject", name)
	}
	subject = strings.TrimSpace(strings.TrimPrefix(rendered[:idx], "Subject:"))
	rest := rendered[idx+1:]
	rest = strings.TrimLeft(rest, "\r\n")
	return subject, rest, nil
}

func (m *smtpMailer) SendOTP(ctx context.Context, email, code string, purpose Purpose, locale Locale) error {
	subject, body, err := RenderOTPMessage(locale, code, purpose)
	if err != nil {
		return fmt.Errorf("render otp message: %w", err)
	}

	msg := buildMessage(m.cfg, email, subject, body)
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))

	deadline := time.Now().UTC().Add(m.cfg.Timeout)
	dialer := &net.Dialer{Deadline: deadline}
	tlsCfg := &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = c.Quit() }()

	auth := smtp.PlainAuth("", m.cfg.User, m.cfg.Password, m.cfg.Host)
	if err := c.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := c.Mail(m.cfg.FromAddress); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err := c.Rcpt(email); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		_ = w.Close()
		return fmt.Errorf("smtp data write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp data close: %w", err)
	}

	m.logger.InfoContext(ctx, "otp mail sent",
		"email", email,
		"purpose", string(purpose),
		"locale", string(locale),
	)
	return nil
}

func buildMessage(cfg SMTPConfig, to, subject, body string) string {
	from := cfg.FromAddress
	if cfg.FromName != "" {
		from = encodeHeaderWord(cfg.FromName) + " <" + cfg.FromAddress + ">"
	}
	headers := []string{
		"From: " + from,
		"To: " + to,
		"Subject: " + encodeHeaderWord(subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: 8bit",
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
	}
	body = strings.ReplaceAll(body, "\r\n", "\n")
	body = strings.ReplaceAll(body, "\n", "\r\n")
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + body
}

func encodeHeaderWord(s string) string {
	hasNonASCII := false
	for _, r := range s {
		if r > 127 {
			hasNonASCII = true
			break
		}
	}
	if !hasNonASCII {
		return s
	}
	const maxRawBytes = 45
	b := []byte(s)
	var words []string
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxRawBytes {
			chunk = b[:maxRawBytes]
			for len(chunk) > 0 && (chunk[len(chunk)-1]&0xC0) == 0x80 {
				chunk = chunk[:len(chunk)-1]
			}
			if len(chunk) == 0 {
				chunk = b[:maxRawBytes]
			}
		}
		words = append(words, "=?UTF-8?B?"+base64.StdEncoding.EncodeToString(chunk)+"?=")
		b = b[len(chunk):]
	}
	return strings.Join(words, " ")
}
