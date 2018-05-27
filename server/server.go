package server

import (
	"context"

	"github.com/mishudark/mondrian"
	"github.com/mishudark/mondrian/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// server is used to access to indentity checker and temprary token creator, via
// gRPC, note that in order to communicate with this server, the caller should
// provide the standard grpc token by `credstore`
type server struct {
	identity mondrian.IdentityValidator
	ticket   mondrian.TicketCreator
}

func (s *server) CreateTicket(ctx context.Context, req *pb.CreateTicketRequest) (*pb.CreateTicketReply, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "request does not contain a user token")
	}

	uid, err := s.identity.ValidateIdentity(ctx, req.UserToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid user token", err)
	}

	ticket, err := s.ticket.CreateTicket(uid)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ticket creation failed %v", err)
	}

	return &pb.CreateTicketReply{
		Ticket: ticket,
	}, nil
}

func (s *server) SigningKey(ctx context.Context, req *pb.SigningKeyRequest) (*pb.SigningKeyReply, error) {
	key, err := s.ticket.SigningKey()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can not get signing key %v", err)
	}
	return &pb.SigningKeyReply{
		SigningKey: key,
	}, nil
}

// New retunrns an instance of Server using the provided services
func New(indentityValidator mondrian.IdentityValidator, tokenCreator mondrian.TicketCreator) pb.MondrianServer {
	return &server{
		identity: indentityValidator,
		ticket:   tokenCreator,
	}
}
