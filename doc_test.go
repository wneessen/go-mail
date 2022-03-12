package mail_test

import (
	"fmt"
	"github.com/wneessen/go-mail"
	"os"
)

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
