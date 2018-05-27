package main

import (
	"flag"
	"net/http"
	"time"

	"github.com/golang/glog"
	"github.com/google/go-microservice-helpers/pki"
	serverhelpers "github.com/google/go-microservice-helpers/server"
	"github.com/google/go-microservice-helpers/tracing"
	"github.com/mishudark/mondrian/identityproviders/providers/devcon"
	"github.com/mishudark/mondrian/pb"
	"github.com/mishudark/mondrian/server"
)

var (
	signingKeyFile = flag.String("signing-key", "", "path to a signing private key")
	ticketDuration = flag.Int("ticket-duration", 5, "max time duration in seconds")
)

func main() {
	flag.Parse()
	defer glog.Flush()

	err := tracing.InitTracer(*serverhelpers.ListenAddress, "credstore")
	if err != nil {
		glog.Exitf("failed to init tracing interface: %v", err)
	}

	signingKey, err := pki.LoadECKeyFromFile(*signingKeyFile)
	if err != nil {
		glog.Exitf("failed to load signing key file: %v", err)
	}

	grpcServer, _, err := serverhelpers.NewServer()
	if err != nil {
		glog.Exitf("error creating a grpc server: %v", err)
	}

	httpCli := &http.Client{
		Timeout: time.Second * 5,
	}

	identity := devcon.NewIdentityChecker(httpCli)
	ticket, err := server.NewTicketCreator(signingKey, time.Second*time.Duration(*ticketDuration))
	if err != nil {
		glog.Exitf("error on new TicketCreator: %v", err)
	}

	svr := server.New(identity, ticket)
	pb.RegisterMondrianServer(grpcServer, svr)

	glog.Error(serverhelpers.ListenAndServe(grpcServer, nil))
}
