package jwt

import (
	"encoding/json"
	"time"
)

// TokenKind is a token used as temporary ticket
const TokenKind = "ticket"

// TicketToken is a JWT temporary token
type TicketToken struct {
	UserID string    `json:"user_id"`
	Kind   string    `json:"kind"`
	Exp    time.Time `json:"exp"`
}

// BuildTicketToken creates and serializes a ticket token
func BuildTicketToken(userID string, duration time.Duration) ([]byte, error) {
	tok := TicketToken{
		UserID: userID,
		Kind:   TokenKind,
		Exp:    time.Now().Add(duration),
	}

	return json.Marshal(tok)
}
