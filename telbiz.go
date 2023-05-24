package telbiz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	// base URL of the Telbiz API
	baseURL = "https://api.telbiz.la/api"

	// timeout for HTTP requests
	timeout = 10 * time.Second
)

// Client is a Telbiz client. It is safe for concurrent use by multiple goroutines.
// The zero value is not usable. Use NewClient to create a client.
type Client struct {
	apiKey    string // provided by Telbiz aka ClientID in the docs
	secretKey string // provided by Telbiz aka Secret in the docs
	token     string
	mu        *sync.Mutex // mu guards token

	// toggleTokenRefresher is used to send a signal to
	// the token refresher goroutine to get a new token.
	toggleTokenRefresher chan struct{}

	hc *http.Client
}

// NewClient creates a new Telbiz client.
func NewClient(ctx context.Context, apiKey, secretKey string) (_ *Client, err error) {
	if apiKey == "" || secretKey == "" {
		return nil, fmt.Errorf("API key and secret must not be empty")
	}

	client := &Client{
		apiKey:    apiKey,
		secretKey: secretKey,
		mu:        new(sync.Mutex),

		toggleTokenRefresher: make(chan struct{}, 1),

		hc: &http.Client{
			Timeout: timeout,
		},
	}

	// get initial token and start token refresher
	token, err := client.connect(ctx)
	if err != nil {
		return nil, err
	}
	client.token = token
	go client.startTokenRefresher(ctx)

	return client, nil
}

// call makes an HTTP request and unmarshals the response into out.
func (c *Client) call(ctx context.Context, req *http.Request, out any) error {
	req2 := req.Clone(ctx)
	injectHeader(req2)

	r, err := c.hc.Do(req2)
	if err != nil {
		return fmt.Errorf("http.Do: %w", err)
	}
	defer r.Body.Close()

	// toggle token refresher if unauthorized
	if r.StatusCode == http.StatusUnauthorized {
		c.toggleTokenRefresher <- struct{}{}
		return errors.New("c.call: unauthorized")
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("io.ReadAll: %w", err)
	}

	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("json.Unmarshal: %w", err)
	}
	return nil
}

// injectHeader injects the required headers into the request.
func injectHeader(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
}

// connect gets a new token from the Telbiz API.
func (c *Client) connect(ctx context.Context) (string, error) {
	url := baseURL + "/v1/connect/token"

	payload, err := json.Marshal(struct {
		ClientID  string `json:"ClientID"`
		Secret    string `json:"Secret"`
		GrantType string `json:"GrantType"`
	}{
		ClientID:  c.apiKey,
		Secret:    c.secretKey,
		GrantType: "client_credentials", // required by Telbiz API. Do not change.
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("http.NewRequestWithContext: %w", err)
	}

	token := new(struct {
		Success     bool   `json:"success"`
		Code        string `json:"code"`
		Message     string `json:"message"`
		AccessToken string `json:"accessToken"`
	})
	if err := c.call(ctx, req, &token); err != nil {
		return "", err
	}
	if !token.Success {
		return "", fmt.Errorf("%s: %s", token.Code, token.Message)
	}

	return token.AccessToken, nil
}

func (c *Client) bearerToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return "Bearer " + c.token
}

// startTokenRefresher starts a goroutine that refreshes the token.
func (c *Client) startTokenRefresher(ctx context.Context) {
	// f is the function that gets a new token and updates the client's token.
	// it will retry with exponential backoff until it gets a new token.
	f := func() {
		backoff := 5 * time.Second
		for {
			token, err := c.connect(ctx)
			if err != nil {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}

			c.mu.Lock()
			c.token = token
			c.mu.Unlock()
		}
	}

	// TODO: make the interval configurable
	ticker := time.NewTicker(30 * time.Minute)
	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			f()
		case <-c.toggleTokenRefresher:
			f()
		}
	}
}

const (
	Default   = "Telbiz"
	News      = "News"
	Promotion = "Promotion"
	OTP       = "OTP"
	Info      = "Info"
	Unknown   = "Unknown"
)

type Message struct {
	// To is a phone number in the format of 20xxxxxxxx or 30xxxxxxx
	To string

	// Title is the title of the message
	// Must be one of the following: Default, News, Promotion, OTP, Info, Unknown
	Title string
	Body  string
}

type SMS struct {
	MessageID string `json:"messageId"`
}

type sendSMSReq struct {
	Phone   string `json:"Phone"`
	Title   string `json:"Title"`
	Message string `json:"Message"`
}

type sendSMSResp struct {
	Status struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Success bool   `json:"success"`
		Detail  string `json:"detail"`
	} `json:"response"`

	Key struct {
		PartitionKey string `json:"partitionKey"`
		RangeKey     string `json:"rangeKey"`
	} `json:"key"`
}

// newSendSMSReq creates a new sendSMSReq from a Message.
func newSendSMSReq(m *Message) (*sendSMSReq, error) {
	if err := validateTitle(m.Title); err != nil {
		return nil, err
	}
	if err := validatePhoneNumber(m.To); err != nil {
		return nil, err
	}

	return &sendSMSReq{
		Phone:   m.To,
		Title:   m.Title,
		Message: m.Body,
	}, nil
}

// validateTitle validates the title of the message.
func validateTitle(title string) error {
	switch title {
	case Default, News, Promotion, OTP, Info, Unknown:
		return nil
	default:
		return errors.New("message title must be one of the following: [Default, News, Promotion, OTP, Info, Unknown]")
	}
}

// validatePhoneNumber validates the phone number.
// it must start with 20 or 30 and must be 9 or 10 digits.
func validatePhoneNumber(phone string) error {
	if _, err := strconv.ParseInt(phone, 10, 64); err != nil {
		return errors.New("phone number must be numeric only")
	}

	if l := len(phone); l < 9 || l > 10 {
		return errors.New("phone number must be 9 or 10 digits")
	}
	if prefix := phone[:2]; prefix != "20" && prefix != "30" {
		return errors.New("phone number must start with 20 or 30")
	}
	return nil
}

// SendSMS sends a message to the Telbiz API.
func (c *Client) SendSMS(ctx context.Context, m *Message) (*SMS, error) {
	message, err := newSendSMSReq(m)
	if err != nil {
		return nil, err
	}

	resp, err := c.sendSMS(ctx, message)
	if err != nil {
		return nil, err
	}
	return &SMS{
		MessageID: resp.Key.RangeKey,
	}, nil
}

func (c *Client) sendSMS(ctx context.Context, m *sendSMSReq) (*sendSMSResp, error) {
	url := baseURL + "/v1/smsservice/newtransaction"

	payload, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("http.NewRequestWithContext: %w", err)
	}
	req.Header.Set("Authorization", c.bearerToken())

	resp := new(sendSMSResp)
	if err := c.call(ctx, req, &resp); err != nil {
		return nil, err
	}
	if !resp.Status.Success {
		return nil, fmt.Errorf("c.sendSMS: %s %s", resp.Status.Code, resp.Status.Message)
	}

	return resp, nil
}
