package telbiz

import (
	"context"
	"testing"
)

// key for test
const (
	apiKey    = "16648132975521747"
	secretKey = "5fd64b00-9fa3-484a-9adb-e6838b99e2b4"
)

func TestNewClient(t *testing.T) {
	ctx := context.Background()
	_, err := NewClient(ctx, "", "")
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = NewClient(ctx, apiKey, "")
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = NewClient(ctx, "", secretKey)
	if err == nil {
		t.Fatal("expected error")
	}

	token, err := NewClient(ctx, apiKey, secretKey)
	if err != nil {
		t.Fatal(err)
	}
	if token == nil {
		t.Fatal("expected token")
	}
}

func TestSendSMS(t *testing.T) {
	ctx := context.Background()
	client, err := NewClient(ctx, apiKey, secretKey)
	if err != nil {
		t.Fatal(err)
	}

	sms, err := client.SendSMS(ctx, &Message{
		To:    "2077805085",
		Title: Info,
		Body:  "jvongxay0308!",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sms.MessageID == "" {
		t.Fatal("expected sms")
	}
}
