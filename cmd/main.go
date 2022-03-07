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
	c, err := mail.NewClient(th, mail.WithTimeout(time.Millisecond*500))
	if err != nil {
		fmt.Printf("failed to create new client: %s\n", err)
		os.Exit(1)
	}

	ctx, cfn := context.WithCancel(context.Background())
	defer cfn()

	if err := c.DialWithContext(ctx); err != nil {
		fmt.Printf("failed to dial: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Client: %+v\n", c)
	fmt.Printf("StartTLS policy: %s\n", c.TLSPolicy())
}
