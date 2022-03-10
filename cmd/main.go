package main

import (
	"context"
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
	c, err := mail.NewClient(th, mail.WithTimeout(time.Millisecond*500), mail.WithTLSPolicy(mail.TLSMandatory),
		mail.WithSMTPAuth(mail.SMTPAuthDigestMD5), mail.WithUsername(tu), mail.WithPassword(tp))
	if err != nil {
		fmt.Printf("failed to create new client: %s\n", err)
		os.Exit(1)
	}
	//c.SetTLSPolicy(mail.TLSMandatory)

	ctx, cfn := context.WithCancel(context.Background())
	defer cfn()

	if err := c.DialWithContext(ctx); err != nil {
		fmt.Printf("failed to dial: %s\n", err)
		os.Exit(1)
	}

	m := mail.NewMsg()
	m.From("wn@neessen.net")
	m.To("test@test.de", "foo@bar.de", "blubb@blah.com")
	m.Cc("cc@test.de", "cc@bar.de", "cc@blah.com")
	m.SetMessageID()
	m.SetBulk()
	m.Header()

}
