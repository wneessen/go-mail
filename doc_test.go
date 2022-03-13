package mail_test

import (
	"fmt"
	"github.com/wneessen/go-mail"
	"os"
)

// Code example for the NewClient method
func ExampleNewClient() {
	c, err := mail.NewClient("mail.example.com")
	if err != nil {
		panic(err)
	}
	_ = c
	// Output:
}

// Code example for the Client.SetTLSPolicy method
func ExampleClient_SetTLSPolicy() {
	c, err := mail.NewClient("mail.example.com")
	if err != nil {
		panic(err)
	}
	c.SetTLSPolicy(mail.TLSMandatory)
	fmt.Println(c.TLSPolicy())
	// Output: TLSMandatory
}

// Code example for the NewMsg method
func ExampleNewMsg() {
	m := mail.NewMsg(mail.WithEncoding(mail.EncodingQP), mail.WithCharset(mail.CharsetASCII))
	fmt.Printf("%s // %s\n", m.Encoding(), m.Charset())
	// Output: quoted-printable // US-ASCII
}

// Code example for the Client.DialAndSend method
func ExampleClient_DialAndSend() {
	from := "Toni Tester <toni@example.com>"
	to := "Alice <alice@example.com>"
	server := "mail.example.com"

	m := mail.NewMsg()
	if err := m.From(from); err != nil {
		fmt.Printf("failed to set FROM address: %s", err)
		os.Exit(1)
	}
	if err := m.To(to); err != nil {
		fmt.Printf("failed to set TO address: %s", err)
		os.Exit(1)
	}
	m.Subject("This is a great subject")

	c, err := mail.NewClient(server)
	if err != nil {
		fmt.Printf("failed to create mail client: %s", err)
		os.Exit(1)
	}
	if err := c.DialAndSend(m); err != nil {
		fmt.Printf("failed to send mail: %s", err)
		os.Exit(1)
	}
}
