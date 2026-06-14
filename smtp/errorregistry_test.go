// SPDX-FileCopyrightText: Copyright (c) The go-mail Authors
//
// SPDX-License-Identifier: MIT

package smtp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"testing"

	"github.com/wneessen/go-mail/internal/helper"
)

type testRegistryErrorHandler struct{}

func (q *testRegistryErrorHandler) HandleError(_, _ string, conn *textproto.Conn, err error) error {
	version, verErr := helper.GetGoVersion(true)
	if verErr != nil {
		return fmt.Errorf("failed to get Go version: %w", err)
	}
	expBytes := []byte(`\x00\x00\x00\x1a\x00\x00\x00`)
	if (version >= 1.2511 && version <= 1.26) || version >= 1.2604 {
		expBytes = []byte(`"\x00\x00\x00\x1a\x00\x00\x00"`)
	}
	var tpErr textproto.ProtocolError
	if errors.As(err, &tpErr) {
		if len(tpErr.Error()) < 16 {
			return err
		}
		if !bytes.Equal([]byte(tpErr.Error()[16:]), expBytes) {
			return err
		}
		_, _ = io.ReadFull(conn.R, make([]byte, 8))
		return nil
	}
	return err
}

func TestNewErrorHandlerRegistry(t *testing.T) {
	t.Run("TestNewErrorHandlerRegistry with all defaults", func(t *testing.T) {
		registry := NewErrorHandlerRegistry()
		if registry == nil {
			t.Fatal("NewErrorHandlerRegistry returned nil")
		}
		if registry.defaultHandler == nil {
			t.Fatal("NewErrorHandlerRegistry returned nil default handler")
		}
		if registry.handlers == nil {
			t.Fatal("NewErrorHandlerRegistry returned nil handlers")
		}
	})
}

func TestErrorHandlerRegistry_Register(t *testing.T) {
	t.Run("TestErrorHandlerRegistry register the test handler", func(t *testing.T) {
		registry := NewErrorHandlerRegistry()
		registry.RegisterHandler("localhost", "HELO", &testRegistryErrorHandler{})
	})
	t.Run("TestErrorHandlerRegistry register nil", func(t *testing.T) {
		registry := NewErrorHandlerRegistry()
		registry.RegisterHandler("localhost", "HELO", nil)
	})
}

func TestErrorHandlerRegistry_GetHandler(t *testing.T) {
	t.Run("TestErrorHandlerRegistry should return testRegistryErrorHandler", func(t *testing.T) {
		registry := NewErrorHandlerRegistry()
		registry.RegisterHandler("localhost", "HELO", &testRegistryErrorHandler{})
		handler := registry.GetHandler("localhost", "HELO")
		if handler == nil {
			t.Fatal("GetHandler returned nil")
		}
		if _, ok := handler.(*testRegistryErrorHandler); !ok {
			t.Errorf("GetHandler returned wrong handler type. expected: %T, got: %T", &testRegistryErrorHandler{},
				handler)
		}
	})
	t.Run("TestErrorHandlerRegistry should return default handler", func(t *testing.T) {
		registry := NewErrorHandlerRegistry()
		registry.RegisterHandler("localhost", "HELO", &testRegistryErrorHandler{})
		handler := registry.GetHandler("localhost", "RCPT TO")
		if handler == nil {
			t.Fatal("GetHandler returned nil")
		}
		if _, ok := handler.(*DefaultErrorHandler); !ok {
			t.Errorf("GetHandler returned wrong handler type. expected: %T, got: %T", &DefaultErrorHandler{},
				handler)
		}
	})
}

func TestErrorHandlerRegistry_SetDefaultHandler(t *testing.T) {
	t.Run("TestErrorHandlerRegistry set the default handler to test handler", func(t *testing.T) {
		registry := NewErrorHandlerRegistry()
		registry.SetDefaultHandler(&testRegistryErrorHandler{})
		handler := registry.GetHandler("localhost", "HELO")
		if handler == nil {
			t.Fatal("GetHandler returned nil")
		}
		if _, ok := handler.(*testRegistryErrorHandler); !ok {
			t.Errorf("GetHandler returned wrong handler type. expected: %T, got: %T", &testRegistryErrorHandler{},
				handler)
		}
	})
}
