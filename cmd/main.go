package main

import (
	"fmt"
	"github.com/wneessen/go-mail"
	"os"
)

func main() {
	th := os.Getenv("TEST_HOST")
	if th == "" {
		fmt.Printf("$TEST_HOST env variable cannot be empty\n")
		os.Exit(1)
	}
	tu := os.Getenv("TEST_USER")
	tp := os.Getenv("TEST_PASS")

	fa := "Winni Neessen <wn@neessen.cloud>"
	toa := "Winfried Neessen <wn@neessen.net>"
	//toa = "Winfried Neessen <wneessen@arch-vm.fritz.box>"

	m := mail.NewMsg()
	if err := m.From(fa); err != nil {
		fmt.Printf("failed to set FROM addres: %s", err)
		os.Exit(1)
	}
	if err := m.To(toa); err != nil {
		fmt.Printf("failed to set TO address: %s", err)
		os.Exit(1)
	}
	m.Subject("This is the Subject with Umlauts: üöäß")
	m.SetHeader(mail.HeaderContentLang, "de", "en", "fr", "sp", "de", "en", "fr", "sp", "de", "en", "fr",
		"sp", "de", "en", "fr", "sp")
	m.SetHeader(mail.HeaderListUnsubscribePost, "üüüüüüüü", "aaaaääää", "ßßßßßßßßß", "XXXXXX", "ZZZZZ", "XXXXXXXX",
		"äää äää", "YYYYYY", "XXXXXX", "ZZZZZ", "üäö´")
	m.SetMessageID()
	m.SetDate()
	m.SetBulk()

	c, err := mail.NewClient(th, mail.WithTLSPolicy(mail.TLSMandatory),
		mail.WithSMTPAuth(mail.SMTPAuthLogin), mail.WithUsername(tu),
		mail.WithPassword(tp))
	if err != nil {
		fmt.Printf("failed to create new client: %s\n", err)
		os.Exit(1)
	}
	if err := c.DialAndSend(m); err != nil {
		fmt.Printf("failed to dial: %s\n", err)
		os.Exit(1)
	}
}
