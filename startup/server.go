package startup

import (
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/application"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/infrastructure/api"
	auth "github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/infrastructure/grpc/proto"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/infrastructure/persistence"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/startup/config"
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
	mailService := server.initMailService()
	productService := server.initProductService(productStore, tokenStore, passwordlessStore)
	productHandler := server.initProductHandler(productService, mailService)

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
		fmt.Println("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
		log.Fatal(err)
	}
	//token, _ := store.GetById(1)
	//fmt.Printf("Tokennnnn%s\n", token.Token)
	for _, Token := range tokens {
		_, err := store.Create(Token)
		if err != nil {
			fmt.Println("FATAAAAALLLLLLLLLLLLLLLLLLLLLLLLLL")
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

func (server *Server) initMailService() *application.MailService {
	return application.NewMailServiceService()
}

func (server *Server) initProductService(store domain.UserStore, tokenStore domain.ForgotPasswordTokenStore, passwordlessStore domain.PasswordlessStore) *application.AuthenticationService {
	return application.NewAuthenticationService(store, tokenStore, passwordlessStore)
}

func (server *Server) initProductHandler(service *application.AuthenticationService, mailService *application.MailService) *api.AuthenticationHandler {
	return api.NewAuthenticationHandler(service, mailService)
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
