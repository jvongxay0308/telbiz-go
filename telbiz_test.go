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

func TestValidatePhoneNumber(t *testing.T) {
	cases := []struct {
		phoneNumber string
		expectedErr bool
	}{
		{phoneNumber: "2022446688", expectedErr: false},
		{phoneNumber: "309988776", expectedErr: false},

		{phoneNumber: "02022446680", expectedErr: true},
		{phoneNumber: "20998877660", expectedErr: true},
		{phoneNumber: "", expectedErr: true},
		{phoneNumber: "xyz", expectedErr: true},
		{phoneNumber: "0022446688", expectedErr: true},
	}

	for _, c := range cases {
		err := validatePhoneNumber(c.phoneNumber)
		if err != nil && !c.expectedErr {
			t.Fatalf("expected no error, got %v", err)
		}
		if err == nil && c.expectedErr {
			t.Fatal("expected error")
		}
	}

}

func TestValidateSMSTitle(t *testing.T) {
	cases := []struct {
		title       string
		expectedErr bool
	}{
		{title: Default, expectedErr: false},
		{title: News, expectedErr: false},
		{title: Promotion, expectedErr: false},
		{title: Info, expectedErr: false},
		{title: OTP, expectedErr: false},
		{title: Unknown, expectedErr: false},
		{title: "xyz", expectedErr: true},
	}

	for _, c := range cases {
		err := validateTitle(c.title)
		if err != nil && !c.expectedErr {
			t.Fatalf("expected no error, got %v", err)
		}
		if err == nil && c.expectedErr {
			t.Fatal("expected error")
		}
	}
}
