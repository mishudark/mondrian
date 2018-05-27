package devcon

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/mishudark/mondrian"
)

const (
	defaultBaseURL      = "https://developer.schibsted.io/"
	headerAuthorization = "Authorization"
)

// Client is used to connect to devcon api
type Client struct {
	httpClient *http.Client
	BaseURL    *url.URL
}

// ValidateIdentity validates the provided token against devcon /whoami endpoint
func (s *Client) ValidateIdentity(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequest("GET", s.BaseURL.String(), nil)
	if err != nil {
		return "", err
	}

	req.Header.Add(headerAuthorization, token)
	resp, err := s.httpClient.Do(req)

	if err != nil {
		// If we got an error, and the context has been canceled,
		// the context's error is probably more useful.
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		return "", err
	}

	return "", checkResponse(resp)
}

func checkResponse(r *http.Response) error {
	if c := r.StatusCode; 200 <= c && c <= 299 {
		return nil
	}

	data, _ := ioutil.ReadAll(r.Body) // nolint: errcheck
	return fmt.Errorf("error status code: %d, message: %s", r.StatusCode, data)
}

// NewIdentityChecker returns a new IdentityChecker using the provided
// http.Client if it is nil, the default will be used
func NewIdentityChecker(httpClient *http.Client) mondrian.IdentityValidator {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	baseURL, _ := url.Parse(defaultBaseURL) // nolint: errcheck
	return &Client{
		httpClient: httpClient,
		BaseURL:    baseURL,
	}
}
