package mondrian

import (
	"context"
)

// IdentityValidator is used to validate an user, it checks the provided token
// with an external service
type IdentityValidator interface {
	ValidateIdentity(ctx context.Context, token string) (userID string, err error)
}

// TicketCreator creates a temorary token, called ticket, this has a
// limited timelife and is used to a service in behalf of the user, the provided
// ticket should be used to any consecutive call, ideally should be sent on
// `ticket` header (authorization header is tipically used by service to service)
type TicketCreator interface {
	CreateTicket(userID string) (ticketToken string, err error)
	SigningKey() ([]byte, error)
}
