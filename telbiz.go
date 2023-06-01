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

// ErrInsufficientFunds is returned when the client
// does not have enough funds to send a message.
var ErrInsufficientFunds = errors.New("insufficient funds")

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
	req2.Header.Set("Authorization", c.bearerToken())
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
		return fmt.Errorf("c.call: io.ReadAll: %w", err)
	}

	if r.StatusCode >= 400 && r.StatusCode < 500 {
		ierr := new(apiErr)
		if err := json.Unmarshal(data, &ierr); err != nil {
			return fmt.Errorf("c.call: json.Unmarshal: %w", err)
		}

		switch ierr.Code {
		case "CREDIT_NOT_SUFFICIENT":
			return fmt.Errorf("c.call: %w", ErrInsufficientFunds)
		default:
			return ierr
		}
	}

	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("c.call: json.Unmarshal: %w", err)
	}
	return nil
}

// apiErr is the error returned by the Telbiz API.
type apiErr struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail"`
}

func (e *apiErr) Error() string {
	return fmt.Sprintf("APIErr: %s: %s", e.Code, e.Message)
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

	resp := new(sendSMSResp)
	if err := c.call(ctx, req, &resp); err != nil {
		return nil, err
	}
	if !resp.Status.Success {
		return nil, fmt.Errorf("c.sendSMS: %s %s", resp.Status.Code, resp.Status.Message)
	}

	return resp, nil
}

// TopUpBalance tops up the balance of a phone number.
type TopUpBalance struct {
	// ID is the ID of the top up transaction
	ID string
	// To is a phone number in the format of 20xxxxxxxx or 30xxxxxxx
	To string
	// Amount is the amount to topup in LAK
	Amount int64
}

type topUpBalanceReq struct {
	Phone  string `json:"phone"`
	Amount int64  `json:"amount"`
}

type topUpBalanceResp struct {
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

// newTopUpBalanceReq creates a new topUpBalanceReq from a TopUpBalance.
func newTopUpBalanceReq(t *TopUpBalance) (*topUpBalanceReq, error) {
	if err := validatePhoneNumber(t.To); err != nil {
		return nil, err
	}
	switch t.Amount / 1000 {
	case 5, 10, 20, 50, 100, 200:
	default:
		return nil, errors.New("amount must be one of the following: [5000, 10000, 20000, 50000, 100000, 200000]")
	}

	return &topUpBalanceReq{
		Phone:  t.To,
		Amount: t.Amount,
	}, nil
}

// TopUpBalance tops up the balance of a phone number.
func (c *Client) TopUpBalance(ctx context.Context, r *TopUpBalance) (*TopUpBalance, error) {
	req, err := newTopUpBalanceReq(r)
	if err != nil {
		return nil, err
	}

	resp, err := c.topUpBalance(ctx, req)
	if err != nil {
		return nil, err
	}
	return &TopUpBalance{
		ID:     resp.Key.RangeKey,
		To:     r.To,
		Amount: r.Amount,
	}, nil
}

func (c *Client) topUpBalance(ctx context.Context, r *topUpBalanceReq) (*topUpBalanceResp, error) {
	url := baseURL + "/v1/topupservice/newtransaction"

	payload, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("http.NewRequestWithContext: %w", err)
	}

	resp := new(topUpBalanceResp)
	if err := c.call(ctx, req, &resp); err != nil {
		return nil, err
	}
	if !resp.Status.Success {
		return nil, fmt.Errorf("c.topUpBalance: %s %s", resp.Status.Code, resp.Status.Message)
	}

	return resp, nil
}

// DataPackagesReq is the request for DataPackages.
type DataPackagesReq struct{}

// DataPackagesResp is the response for DataPackages.
type DataPackagesResp struct {
	Packages []*DataPackage `json:"packages"`
}

// DataPackage is a data package available for purchase.
type DataPackage struct {
	// ID is the ID of the data package.
	// it is used to purchase the data package.
	ID string `json:"id"`
	// DisplayName is the display name of the data package.
	DisplayName string `json:"name"`
	// Description is the description of the data package.
	Description string `json:"description"`
	// Price is the price of the data package in LAK.
	Price int64 `json:"price"`
	// NSs is a slice of DataPackageNS for each ISP.
	NSs []DataPackageNS `json:"nss"`
}

// DataPackageNS is a data package for a specific ISP.
type DataPackageNS struct {
	// ISP is the Internet Service Provider of the data package.
	ISP    string `json:"isp"` // [LTC, TPLUS, UNITEL, ETL, BEST]
	NSCode string `json:"nsCode"`
	NMCode string `json:"nmCode"`
	// AmountGB is the amount of data you get in GB.
	AmountGB int64 `json:"amountGB"`
	// DurationDays is usable duration of the data package in days.
	DurationDays int `json:"durationDays"`
}

// dataPackageResp is the response for DataPackages from the Telbiz API.
type dataPackageResp struct {
	Name           string `json:"name"`
	ID             string `json:"id"`
	Type           string `json:"type"`
	Description    string `json:"description"`
	LTCNSCode      string `json:"ltcNSCode"`
	LTCNMCode      string `json:"ltcNMCode"`
	TPlusNSCode    string `json:"tPlusNSCode"`
	TPlusNMCode    string `json:"tPlusNMCode"`
	UnitelNSCode   string `json:"unitelNSCode"`
	UnitelNMCode   string `json:"unitelNMCode"`
	ETLNSCode      string `json:"etlNSCode"`
	ETLNMCode      string `json:"etlNMCode"`
	BestNSCode     string `json:"bestNSCode"`
	BestNMCode     string `json:"bestNMCode"`
	Price          int64  `json:"price"`
	LTCNSAmount    int64  `json:"ltcNSAmount"`
	LTCNMAmount    int64  `json:"ltcNMAmount"`
	TplusNSAmount  int64  `json:"tplusNSAmount"`
	TplusNMAmount  int64  `json:"tplusNMAmount"`
	UnitelNSAmount int64  `json:"unitelNSAmount"`
	UnitelNMAmount int64  `json:"unitelNMAmount"`
	EtlNSAmount    int64  `json:"etlNSAmount"`
	EtlNMAmount    int64  `json:"etlNMAmount"`
	LTCNSDays      int    `json:"ltcNSDays"`
	LTCNMDays      int    `json:"ltcNMDays"`
	TplusNSDays    int    `json:"tplusNSDays"`
	TplusNMDays    int    `json:"tplusNMDays"`
	ETLNSDays      int    `json:"etlNSDays"`
	ETLNMDays      int    `json:"etlNMDays"`
	UnitelNSDays   int    `json:"unitelNSDays"`
	UnitelNMDays   int    `json:"unitelNMDays"`
}

// newDataPackage creates a new DataPackage from a dataPackageResp.
func newDataPackage(dp *dataPackageResp) *DataPackage {
	p := &DataPackage{
		ID:          dp.ID,
		DisplayName: dp.Name,
		Description: dp.Description,
		Price:       dp.Price,
		NSs:         []DataPackageNS{},
	}

	if dp.ETLNSCode != "" {
		p.NSs = append(p.NSs, DataPackageNS{
			ISP:          "ETL",
			NSCode:       dp.ETLNSCode,
			NMCode:       dp.ETLNMCode,
			AmountGB:     dp.EtlNSAmount / 1024,
			DurationDays: dp.ETLNSDays,
		})
	}
	if dp.LTCNSCode != "" {
		p.NSs = append(p.NSs, DataPackageNS{
			ISP:          "LTC",
			NSCode:       dp.LTCNSCode,
			NMCode:       dp.LTCNMCode,
			AmountGB:     dp.LTCNSAmount / 1024,
			DurationDays: dp.LTCNSDays,
		})
	}
	if dp.TPlusNSCode != "" {
		p.NSs = append(p.NSs, DataPackageNS{
			ISP:          "TPLUS",
			NSCode:       dp.TPlusNSCode,
			NMCode:       dp.TPlusNMCode,
			AmountGB:     dp.TplusNSAmount / 1024,
			DurationDays: dp.TplusNSDays,
		})
	}
	if dp.UnitelNSCode != "" {
		p.NSs = append(p.NSs, DataPackageNS{
			ISP:          "UNITEL",
			NSCode:       dp.UnitelNSCode,
			NMCode:       dp.UnitelNMCode,
			AmountGB:     dp.UnitelNSAmount / 1024,
			DurationDays: dp.UnitelNSDays,
		})
	}
	if dp.BestNSCode != "" {
		p.NSs = append(p.NSs, DataPackageNS{
			ISP:    "BEST",
			NSCode: dp.BestNSCode,
			NMCode: dp.BestNMCode,
		})
	}

	return p
}

// newDataPackages creates a slice of DataPackages from a slice of dataPackageResp.
func newDataPackages(packages []*dataPackageResp) []*DataPackage {
	p := make([]*DataPackage, len(packages))
	for i, dp := range packages {
		p[i] = newDataPackage(dp)
	}
	return p
}

// DataPackages lists all available data packages.
func (c *Client) DataPackages(ctx context.Context, _ *DataPackagesReq) (*DataPackagesResp, error) {
	url := baseURL + "/v1/DataService/listdatapackage"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequestWithContext: %w", err)
	}

	resp := make([]*dataPackageResp, 0)
	if err := c.call(ctx, req, &resp); err != nil {
		return nil, err
	}

	return &DataPackagesResp{
		Packages: newDataPackages(resp),
	}, nil
}

// TopUpDataPackageReq is the request for TopUpDataPackageReq
// to purchase a data package.
type TopUpDataPackageReq struct {
	// PackageID is the ID of the data package to purchase.
	PackageID string
	// To is a phone number in the format of 20xxxxxxxx or 30xxxxxxx
	To string
}

// TopUpDataPackageTx is the transaction for TopUpDataPackage.
// it is returned when TopUpDataPackage is successful.
type TopUpDataPackageTx struct {
	// ID is the ID of the top up transaction returned by the Telbiz API.
	ID string
	// PackageID is the ID of the data package to purchase.
	PackageID string
	// To is a phone number in the format of 20xxxxxxxx or 30xxxxxxx
	To string
}

type topUpDataPackageReq struct {
	Phone     string `json:"phone"`
	PackageID string `json:"packageId"`
}

type topUpDataPackageResp struct {
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

// newTopUpDataPackageReq creates a new topUpDataPackageReq from a TopUpDataPackageReq.
func newTopUpDataPackageReq(t *TopUpDataPackageReq) (*topUpDataPackageReq, error) {
	if t == nil {
		return nil, errors.New("newTopUpDataPackageReq: TopUpDataPackageReq must not be nil")
	}
	if err := validatePhoneNumber(t.To); err != nil {
		return nil, err
	}
	if t.PackageID == "" {
		return nil, errors.New("package ID must not be empty")
	}

	return &topUpDataPackageReq{
		Phone:     t.To,
		PackageID: t.PackageID,
	}, nil
}

// TopUpDataPackage tops up a data package.
func (c *Client) TopUpDataPackage(ctx context.Context, req *TopUpDataPackageReq) (*TopUpDataPackageTx, error) {
	r, err := newTopUpDataPackageReq(req)
	if err != nil {
		return nil, err
	}

	resp, err := c.topUpDataPackage(ctx, r)
	if err != nil {
		return nil, err
	}
	return &TopUpDataPackageTx{
		ID:        resp.Key.RangeKey,
		PackageID: r.PackageID,
		To:        r.Phone,
	}, nil
}

func (c *Client) topUpDataPackage(ctx context.Context, r *topUpDataPackageReq) (*topUpDataPackageResp, error) {
	url := baseURL + "/v1/DataService/newtransaction"

	payload, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("http.NewRequestWithContext: %w", err)
	}

	resp := new(topUpDataPackageResp)
	if err := c.call(ctx, req, &resp); err != nil {
		return nil, err
	}
	if !resp.Status.Success {
		return nil, fmt.Errorf("c.topUpDataPackage: %s %s", resp.Status.Code, resp.Status.Message)
	}

	return resp, nil
}
