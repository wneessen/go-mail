// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail_test

import (
	"context"
	"fmt"
	"os"
	"text/template"
	"time"

	"github.com/wneessen/go-mail"
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

// This code example shows how to use Msg.SetBodyString to set a string as message body with
// different content types
func ExampleMsg_SetBodyString_differentTypes() {
	m := mail.NewMsg()
	m.SetBodyString(mail.TypeTextPlain, "This is a mail body that with content type: text/plain")
	m.SetBodyString(mail.TypeTextHTML, "<p>This is a mail body that with content type: text/html</p>")
}

// This code example shows how to use Msg.SetBodyString to set a string as message body a PartOption
// to override the default encoding
func ExampleMsg_SetBodyString_withPartOption() {
	m := mail.NewMsg(mail.WithEncoding(mail.EncodingB64))
	m.SetBodyString(mail.TypeTextPlain, "This is a mail body that with content type: text/plain",
		mail.WithPartEncoding(mail.EncodingQP))
}

// This code example shows how to use a text/template as message Body.
// Msg.SetBodyHTMLTemplate works anolog to this just with html/template instead
func ExampleMsg_SetBodyTextTemplate() {
	type MyStruct struct {
		Placeholder string
	}
	data := MyStruct{Placeholder: "Teststring"}
	tpl, err := template.New("test").Parse("This is a {{.Placeholder}}")
	if err != nil {
		panic(err)
	}

	m := mail.NewMsg()
	if err := m.SetBodyTextTemplate(tpl, data); err != nil {
		panic(err)
	}
}

// This code example shows how to utilize the Msg.WriteToSendmail method to send generated mails
// using a local sendmail installation
func ExampleMsg_WriteToSendmail() {
	m := mail.NewMsg()
	m.SetBodyString(mail.TypeTextPlain, "This is the mail body string")
	if err := m.FromFormat("Toni Tester", "toni.tester@example.com"); err != nil {
		panic(err)
	}
	if err := m.To("gandalf.tester@example.com"); err != nil {
		panic(err)
	}
	if err := m.WriteToSendmail(); err != nil {
		panic(err)
	}
}

// This code example shows how to send generated mails using a custom context and sendmail-compatbile command
// using the Msg.WriteToSendmailWithContext method
func ExampleMsg_WriteToSendmailWithContext() {
	sendmailPath := "/opt/sendmail/sbin/sendmail"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	m := mail.NewMsg()
	m.SetBodyString(mail.TypeTextPlain, "This is the mail body string")
	if err := m.FromFormat("Toni Tester", "toni.tester@example.com"); err != nil {
		panic(err)
	}
	if err := m.To("gandalf.tester@example.com"); err != nil {
		panic(err)
	}
	if err := m.WriteToSendmailWithContext(ctx, sendmailPath); err != nil {
		panic(err)
	}
}
