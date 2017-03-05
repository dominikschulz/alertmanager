package notify

import (
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"

	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/template"
	"github.com/prometheus/alertmanager/types"
	"github.com/prometheus/common/log"
	"golang.org/x/net/context"
)

// Email implements a Notifier for email notifications.
type Email struct {
	conf *config.EmailConfig
	tmpl *template.Template
}

// NewEmail returns a new Email notifier.
func NewEmail(c *config.EmailConfig, t *template.Template) *Email {
	if _, ok := c.Headers["Subject"]; !ok {
		c.Headers["Subject"] = config.DefaultEmailSubject
	}
	if _, ok := c.Headers["To"]; !ok {
		c.Headers["To"] = c.To
	}
	if _, ok := c.Headers["From"]; !ok {
		c.Headers["From"] = c.From
	}
	log.Debugf("Created NewEmail config: %+v", c)
	return &Email{conf: c, tmpl: t}
}

// auth resolves a string of authentication mechanisms.
func (n *Email) auth(mechs string) (smtp.Auth, error) {
	username := n.conf.AuthUsername

	for _, mech := range strings.Split(mechs, " ") {
		switch mech {
		case "CRAM-MD5":
			secret := string(n.conf.AuthSecret)
			if secret == "" {
				continue
			}
			return smtp.CRAMMD5Auth(username, secret), nil

		case "PLAIN":
			password := string(n.conf.AuthPassword)
			if password == "" {
				continue
			}
			identity := n.conf.AuthIdentity

			// We need to know the hostname for both auth and TLS.
			host, _, err := net.SplitHostPort(n.conf.Smarthost)
			if err != nil {
				return nil, fmt.Errorf("invalid address: %s", err)
			}
			return smtp.PlainAuth(identity, username, password, host), nil
		case "LOGIN":
			password := string(n.conf.AuthPassword)
			if password == "" {
				continue
			}
			return LoginAuth(username, password), nil
		}
	}
	return nil, nil
}

// Notify implements the Notifier interface.
func (n *Email) Notify(ctx context.Context, as ...*types.Alert) (bool, error) {
	// Connect to the SMTP smarthost.
	c, err := smtp.Dial(n.conf.Smarthost)
	if err != nil {
		return true, err
	}
	defer c.Quit()

	// We need to know the hostname for both auth and TLS.
	host, _, err := net.SplitHostPort(n.conf.Smarthost)
	if err != nil {
		return false, fmt.Errorf("invalid address: %s", err)
	}

	// Global Config guarantees RequireTLS is not nil
	if *n.conf.RequireTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return true, fmt.Errorf("require_tls: true (default), but %q does not advertise the STARTTLS extension", n.conf.Smarthost)
		}
		tlsConf := &tls.Config{ServerName: host}
		if err := c.StartTLS(tlsConf); err != nil {
			return true, fmt.Errorf("starttls failed: %s", err)
		}
	}

	if ok, mech := c.Extension("AUTH"); ok {
		auth, err := n.auth(mech)
		if err != nil {
			return true, err
		}
		if auth != nil {
			if err := c.Auth(auth); err != nil {
				return true, fmt.Errorf("%T failed: %s", auth, err)
			}
		}
	}

	var (
		data = n.tmpl.Data(receiverName(ctx), groupLabels(ctx), as...)
		tmpl = tmplText(n.tmpl, data, &err)
		from = tmpl(n.conf.From)
		to   = tmpl(n.conf.To)
	)
	if err != nil {
		return false, err
	}

	addrs, err := mail.ParseAddressList(from)
	if err != nil {
		return false, fmt.Errorf("parsing from addresses: %s", err)
	}
	if len(addrs) != 1 {
		return false, fmt.Errorf("must be exactly one from address")
	}
	if err := c.Mail(addrs[0].Address); err != nil {
		return true, fmt.Errorf("sending mail from: %s", err)
	}
	addrs, err = mail.ParseAddressList(to)
	if err != nil {
		return false, fmt.Errorf("parsing to addresses: %s", err)
	}
	for _, addr := range addrs {
		if err := c.Rcpt(addr.Address); err != nil {
			return true, fmt.Errorf("sending rcpt to: %s", err)
		}
	}

	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		return true, err
	}
	defer wc.Close()

	for header, t := range n.conf.Headers {
		value, err := n.tmpl.ExecuteTextString(t, data)
		if err != nil {
			return false, fmt.Errorf("executing %q header template: %s", header, err)
		}
		fmt.Fprintf(wc, "%s: %s\r\n", header, mime.QEncoding.Encode("utf-8", value))
	}

	fmt.Fprintf(wc, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(wc, "X-P8s-Status: %s\r\n", data.Status)
	fmt.Fprintf(wc, "X-P8s-URL: %s\r\n", data.ExternalURL)
	fmt.Fprintf(wc, "MIME-Version: 1.0\r\n")

	mw := multipart.NewWriter(wc)
	defer mw.Close()
	fmt.Fprintf(wc, "Content-Type: multipart/mixed; boundary=%s\r\n", mw.Boundary())
	// TODO(dschulz) add List header for easy filtering

	fmt.Fprintf(wc, "\r\n")

	htmlWriter, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type": []string{"text/html"},
	})
	if err != nil {
		return true, err
	}
	htmlBody, err := n.tmpl.ExecuteHTMLString(n.conf.HTML, data)
	if err != nil {
		return false, fmt.Errorf("executing email html template: %s", err)
	}
	_, err = io.WriteString(htmlWriter, htmlBody)
	if err != nil {
		return true, err
	}

	plainWriter, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type": []string{"text/plain"},
	})
	if err != nil {
		return true, err
	}
	plainBody, err := n.tmpl.ExecuteTextString(n.conf.Plain, data)
	if err != nil {
		return false, fmt.Errorf("executing email plain template: %s", err)
	}
	_, err = io.WriteString(plainWriter, plainBody)
	if err != nil {
		return true, err
	}

	log.Debugf("Sent email to %+v", addrs)

	return false, nil
}
