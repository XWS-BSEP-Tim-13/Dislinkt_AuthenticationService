package startup

import (
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/application"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/infrastructure/api"
	auth "github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/infrastructure/grpc/proto"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/infrastructure/persistence"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/startup/config"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/util"
	"google.golang.org/grpc"
	"gorm.io/gorm"
	"log"
	"net"
)

type Server struct {
	config *config.Config
}

func NewServer(config *config.Config) *Server {
	return &Server{
		config: config,
	}
}

func (server *Server) Start() {
	postgresClient := server.initPostgresClient()
	productStore := server.initProductStore(postgresClient)
	tokenStore := server.initTokenStore(postgresClient)
	passwordlessStore := server.initPasswordlessStore(postgresClient)
	verificationStore := server.initVerificationStore(postgresClient)
	mailService := server.initMailService()
	goValidator := server.initGoValidator()
	productService := server.initAuthenticationService(productStore, tokenStore, passwordlessStore, verificationStore, mailService)
	productHandler := server.initAuthenticationHandler(productService, mailService, goValidator)

	server.startGrpcServer(productHandler)
}

func (server *Server) initPostgresClient() *gorm.DB {
	client, err := persistence.GetClient(
		server.config.AuthDBHost, server.config.AuthDBUser,
		server.config.AuthDBPass, server.config.AuthDBName,
		server.config.AuthDBPort)
	if err != nil {
		log.Fatal(err)
	}
	return client
}
func (server *Server) initTokenStore(client *gorm.DB) domain.ForgotPasswordTokenStore {
	store, err := persistence.NewForgotPasswordTokenPostgresStore(client)
	store.DeleteAll()
	if err != nil {
		log.Fatal(err)
	}
	//token, _ := store.GetById(1)
	//fmt.Printf("Tokennnnn%s\n", token.Token)
	for _, Token := range tokens {
		_, err := store.Create(Token)
		if err != nil {
			log.Fatal(err)
		}
	}
	return store
}

func (server *Server) initProductStore(client *gorm.DB) domain.UserStore {
	store, err := persistence.NewAuthenticationPostgresStore(client)
	if err != nil {
		log.Fatal(err)
	}
	store.DeleteAll()
	for _, User := range users {
		_, err := store.Create(User)
		if err != nil {
			log.Fatal(err)
		}
	}
	return store
}

func (server *Server) initPasswordlessStore(client *gorm.DB) domain.PasswordlessStore {
	store, err := persistence.NewPasswordlessPostgresStore(client)
	if err != nil {
		log.Fatal(err)
	}
	return store
}

func (server *Server) initVerificationStore(client *gorm.DB) domain.VerificationStore {
	store, err := persistence.NewVerificationPostgresStore(client)
	if err != nil {
		log.Fatal(err)
	}
	return store
}

func (server *Server) initMailService() *application.MailService {
	return application.NewMailServiceService()
}

func (server *Server) initGoValidator() *util.GoValidator {
	return util.NewGoValidator()
}

func (server *Server) initAuthenticationService(store domain.UserStore, tokenStore domain.ForgotPasswordTokenStore, passwordlessStore domain.PasswordlessStore, verificationStore domain.VerificationStore, mailService *application.MailService) *application.AuthenticationService {
	return application.NewAuthenticationService(store, tokenStore, passwordlessStore, verificationStore, mailService)
}

func (server *Server) initAuthenticationHandler(service *application.AuthenticationService, mailService *application.MailService, goValidator *util.GoValidator) *api.AuthenticationHandler {
	return api.NewAuthenticationHandler(service, mailService, goValidator)
}

func (server *Server) startGrpcServer(authenticationHandler *api.AuthenticationHandler) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", server.config.Port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	auth.RegisterAuthenticationServiceServer(grpcServer, authenticationHandler)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}
}
