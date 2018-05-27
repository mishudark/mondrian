package client

import (
	"context"
	"crypto"
	"encoding/json"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// HTTPMondrianHandler is a middleware arond HandlerFunc, it uses the public key
// from mondrian the user ticket token
// it should be provided in the form of `Bearer token` in the header `ticket`
func HTTPMondrianHandler(handler http.HandlerFunc, publicKey crypto.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get(HeaderKey)
		if token == "" {
			errorHandler(w, r, "missing ticket token")
			return
		}

		_, err := ValidateTicketToken(token, publicKey)
		if err != nil {
			errorHandler(w, r, err.Error())
			return
		}

		handler(w, r)
	}
}

func errorHandler(w http.ResponseWriter, r *http.Request, description string) {
	json.NewEncoder(w).Encode(struct { // nolint:errcheck
		Description string `json:"description"`
	}{
		Description: description,
	})
	w.WriteHeader(401)
}

// MondrianTokenInterceptor returns a new unary server interceptor that performs per-request auth.
// additionaly it puts the userID under UserIDContextKey header in context
func MondrianTokenInterceptor(publicKey crypto.PublicKey) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		var newCtx context.Context
		var err error

		md, ok := metadata.FromIncomingContext(ctx)
		if ok == false {
			return nil, status.Errorf(codes.Unauthenticated, "cannot read metadata for request")
		}

		tok := md[HeaderKey]
		if len(tok) != 1 {
			return nil, status.Errorf(codes.Unauthenticated, "bad authorization string")
		}

		rawToken := tok[0]
		if rawToken == "" {
			return nil, status.Errorf(codes.Unauthenticated, "authorization header is missing")
		}

		userID, err := ValidateTicketToken(rawToken, publicKey)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}

		token, _ := extractToken(rawToken) // nolint:errcheck
		newCtx = context.WithValue(ctx, TicketTokenContextKey, token)
		newCtx = context.WithValue(newCtx, UserIDContextKey, userID)

		return handler(newCtx, req)
	}
}
