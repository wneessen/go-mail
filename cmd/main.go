package main

import (
	"context"
	"crypto/tls"
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
	c, err := mail.NewClient(th, mail.WithTimeout(time.Millisecond*500), mail.WithTLSPolicy(mail.TLSOpportunistic))
	if err != nil {
		fmt.Printf("failed to create new client: %s\n", err)
		os.Exit(1)
	}
	//c.SetTLSPolicy(mail.TLSMandatory)
	tc := &tls.Config{
		ServerName: th,
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS10,
	}
	c.SetTLSConfig(tc)

	ctx, cfn := context.WithCancel(context.Background())
	defer cfn()

	if err := c.DialWithContext(ctx); err != nil {
		fmt.Printf("failed to dial: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Client: %+v\n", c)
	fmt.Printf("StartTLS policy: %s\n", c.TLSPolicy())
}
