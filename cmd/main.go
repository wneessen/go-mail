package main

import (
	"fmt"
	"github.com/wneessen/go-mail"
	"os"
	"time"
)

func main() {
	th := os.Getenv("TEST_HOST")
	if th == "" {
		fmt.Printf("$TEST_HOST env variable cannot be empty\n")
		os.Exit(1)
	}
	tu := os.Getenv("TEST_USER")
	tp := os.Getenv("TEST_PASS")

	m := mail.NewMsg()
	if err := m.From(`Winni Neessen <wn@neessen.net>`); err != nil {
		fmt.Printf("failed to set FROM addres: %s", err)
		os.Exit(1)
	}
	m.ToIgnoreInvalid("test@test.de", "foo@bar.de", "blubb@blah.com")
	m.CcIgnoreInvalid("cc@test.de", "bar.de", "cc@blah.com")
	m.BccIgnoreInvalid("bcc@test.de", "bcc@blah.com")
	m.SetHeader("Foo", "bar")
	m.SetMessageID()
	m.SetDate()
	m.SetBulk()
	m.Header()

	c, err := mail.NewClient(th, mail.WithTimeout(time.Millisecond*500), mail.WithTLSPolicy(mail.TLSMandatory),
		mail.WithSMTPAuth(mail.SMTPAuthDigestMD5), mail.WithUsername(tu), mail.WithPassword(tp))
	if err != nil {
		fmt.Printf("failed to create new client: %s\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := c.Close(); err != nil {
			fmt.Printf("failed to close: %s\n", err)
			os.Exit(1)
		}
	}()

	if err := c.DialAndSend(); err != nil {
		fmt.Printf("failed to dial: %s\n", err)
		os.Exit(1)
	}
}
