package client

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	clienthelpers "github.com/google/go-microservice-helpers/client"
	"github.com/mishudark/mondrian/jwt"
	"github.com/mishudark/mondrian/pb"
	"google.golang.org/grpc/metadata"
	jose "gopkg.in/square/go-jose.v2"
)

type contextKey string

// HeaderKey is on headers to attach a ticket token
const (
	HeaderKey = "ticket"
	bearer    = "bearer"
	bearerTpl = "Bearer %s"

	TicketTokenContextKey contextKey = "ticketToken"
	UserIDContextKey      contextKey = "userID"
)

// WithGRPCBearerToken adds bearer ticket token to the context.
func WithGRPCBearerToken(ctx context.Context, token string) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	} else {
		md = md.Copy()
	}

	md[HeaderKey] = []string{fmt.Sprintf("%s %s", bearer, token)}

	ctx = metadata.NewOutgoingContext(ctx, md)
	return ctx
}

// WithHTTPBearerToken adds ticket bearer token to headers
func WithHTTPBearerToken(req *http.Request, token string) {
	req.Header.Add(HeaderKey, fmt.Sprintf(bearerTpl, token))
}

// HTTPToContext moves ticket token from headers to context
func HTTPToContext(ctx context.Context, r *http.Request) context.Context {
	token, err := extractToken(r.Header.Get(HeaderKey))
	if err != nil {
		return ctx
	}

	return context.WithValue(ctx, TicketTokenContextKey, token)
}

func extractToken(token string) (string, error) {
	splits := strings.SplitN(token, " ", 2)

	if len(splits) < 2 {
		return "", errors.New("bad authorization string")
	}

	if strings.ToLower(splits[0]) != strings.ToLower(bearer) {
		return "", errors.New("request unauthenticated with 'bearer'")
	}

	return splits[1], nil
}

// ValidateTicketToken validates provided token against mondrian public key
func ValidateTicketToken(token string, publicKey crypto.PublicKey) (userID string, err error) {
	jwtTokString, err := extractToken(token)
	if err != nil {
		return userID, err
	}

	jwtTok, err := jose.ParseSigned(jwtTokString)
	if err != nil {
		return userID, fmt.Errorf("failed to parse token: %v", err)
	}

	payload, err := jwtTok.Verify(publicKey)
	if err != nil {
		return userID, fmt.Errorf("failed to verify token: %v", err)
	}

	var ticketTok jwt.TicketToken
	err = json.Unmarshal(payload, &ticketTok)

	return ticketTok.UserID, err
}

// MondrianClient is used to communicate with mondrian server
type MondrianClient struct {
	cli pb.MondrianClient
}

// NewMondrianClient returns a new MondrianClient
func NewMondrianClient(ctx context.Context, mondrianAddress string, credStoreCA string) (*MondrianClient, error) {
	conn, err := clienthelpers.NewGRPCConn(mondrianAddress, credStoreCA, "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create connection to credstore: %v", err)
	}

	return &MondrianClient{
		cli: pb.NewMondrianClient(conn),
	}, nil
}

// SigningKey gets mondrian public key
func (c *MondrianClient) SigningKey(ctx context.Context) (crypto.PublicKey, error) {
	resp, err := c.cli.SigningKey(ctx, &pb.SigningKeyRequest{})
	if err != nil {
		return nil, err
	}

	pubkey, err := x509.ParsePKIXPublicKey(resp.GetSigningKey())
	if err != nil {
		return nil, err
	}

	if k, ok := pubkey.(crypto.PublicKey); ok {
		return k, nil
	}
	return nil, fmt.Errorf("cannot parse the public key")
}

// CreateTicket gets a new ticket on behalf of the user
func (c *MondrianClient) CreateTicket(ctx context.Context, token string) (string, error) {
	resp, err := c.cli.CreateTicket(ctx, &pb.CreateTicketRequest{
		UserToken: token,
	})
	if err != nil {
		return "", err
	}

	return resp.Ticket, nil
}
