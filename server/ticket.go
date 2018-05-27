package server

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/mishudark/mondrian"
	"github.com/mishudark/mondrian/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	jose "gopkg.in/square/go-jose.v2"
)

type ticketService struct {
	signingKey *ecdsa.PrivateKey
	signer     jose.Signer
	duration   time.Duration
}

func (s *ticketService) CreateTicket(userID string) (ticketToken string, err error) {
	token, err := jwt.BuildTicketToken(userID, s.duration)
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to serialize JWT token: %v", err)
	}

	object, err := s.signer.Sign(token)
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to sign JWT payload: %v", err)
	}

	serialized, err := object.CompactSerialize()
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to serialize short-form token: %v", err)
	}

	return serialized, nil
}

func (s *ticketService) SigningKey() ([]byte, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(s.signingKey.Public())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal ec public key: %v", err)
	}

	return pubkeyBytes, nil
}

// NewTicketCreator returns an api.TicketCreator
func NewTicketCreator(signingKey *ecdsa.PrivateKey, duration time.Duration) (mondrian.TicketCreator, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES384, Key: signingKey},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{"typ": "JWT"},
		})

	if err != nil {
		return nil, fmt.Errorf("failed to create JWT signer: %v", err)
	}

	return &ticketService{
		signingKey: signingKey,
		signer:     signer,
		duration:   duration,
	}, nil
}
