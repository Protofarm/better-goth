package smtp

import (
	"crypto/tls"
	"fmt"
	netsmtp "net/smtp"
	"strings"
	"time"
)

type Config struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
}

type Mailer struct {
	cfg Config
}

func NewMailer(cfg Config) *Mailer {
	return &Mailer{cfg: cfg}
}

func (m *Mailer) Enabled() bool {
	return m != nil && strings.TrimSpace(m.cfg.Host) != ""
}

func (m *Mailer) SendPasswordResetEmail(to, code string) error {
	body := "Your password reset code is: " + code + "\r\n\r\nThis code expires in 10 minutes.\r\n"
	return m.SendPlainEmail(to, "Your password reset code", body)
}

func (m *Mailer) SendPlainEmail(to, subject, body string) error {
	if !m.Enabled() {
		return fmt.Errorf("smtp is not configured")
	}
	tlsConn, err := tls.Dial("tcp", m.cfg.Host+":"+m.cfg.Port, &tls.Config{
		ServerName: m.cfg.Host,
	})
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}

	conn, err := netsmtp.NewClient(tlsConn, m.cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer conn.Close()

	if err = conn.Auth(netsmtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)); err != nil {
		return fmt.Errorf("auth: %w", err)
	}

	if err = conn.Mail(m.cfg.From); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	if err = conn.Rcpt(to); err != nil {
		return fmt.Errorf("rcpt to: %w", err)
	}

	wc, err := conn.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	if _, err = fmt.Fprint(wc, m.buildMsg(to, subject, body)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err = wc.Close(); err != nil {
		return fmt.Errorf("close data: %w", err)
	}

	return conn.Quit()
}

func (m *Mailer) SendVerificationEmail(to, verifyURL string) error {
	return m.SendPlainEmail(to, "Verify your email address",
		"Please verify your email address by clicking the link below:\r\n\r\n"+verifyURL+"\r\n\r\nThis link expires in 15 minutes.\r\n")
}

func (m *Mailer) buildMsg(to, subject, body string) string {
	var b strings.Builder
	b.WriteString("From: " + m.cfg.From + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}
