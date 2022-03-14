package main

import (
	"flag"
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

	fa := "Winni Neessen <wn@neessen.cloud>"
	toa := "Winfried Neessen <wn@neessen.net>"
	//toa = "Winfried Neessen <wneessen@arch-vm.fritz.box>"

	m := mail.NewMsg()
	if err := m.From(fa); err != nil {
		fmt.Printf("failed to set FROM address: %s", err)
		os.Exit(1)
	}
	if err := m.To(toa); err != nil {
		fmt.Printf("failed to set TO address: %s", err)
		os.Exit(1)
	}
	m.Subject("This is a mail with attachments")
	m.SetMessageID()
	m.SetDate()
	m.SetBulk()
	m.SetBodyString(mail.TypeTextPlain, "This should have an attachment.")

	f, err := os.Open("/home/wneessen/certs.csv")
	if err != nil {
		fmt.Printf("failed to open file for reading: %s\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Printf("failed to close file: %s\n", err)
			os.Exit(1)
		}
	}()
	m.AttachReader("certs.csv", f, mail.WithFileName("test.txt"))

	sendMail := flag.Bool("send", false, "wether to send mail or output to STDOUT")
	flag.Parse()
	if !*sendMail {
		_, err := m.Write(os.Stdout)
		if err != nil {
			fmt.Printf("failed to write mail: %s\n", err)
			os.Exit(1)
		}
	} else {
		tu := os.Getenv("TEST_USER")
		tp := os.Getenv("TEST_PASS")
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
}
