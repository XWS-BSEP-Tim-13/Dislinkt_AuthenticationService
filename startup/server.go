package startup

import (
	"fmt"
	"net"
	//inventory "github.com/tamararankovic/microservices_demo/common/proto/inventory_service"
	/*"github.com/tamararankovic/microservices_demo/inventory_service/application"
	"github.com/tamararankovic/microservices_demo/inventory_service/domain"
	"github.com/tamararankovic/microservices_demo/inventory_service/infrastructure/api"
	"github.com/tamararankovic/microservices_demo/inventory_service/infrastructure/persistence"*/
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/startup/config"
	"google.golang.org/grpc"
	"gorm.io/gorm"
	"log"
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
	productService := server.initProductService(productStore)
	productHandler := server.initProductHandler(productService)

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

func (server *Server) initProductStore(client *gorm.DB) domain.ProductStore {
	store, err := persistence.NewProductPostgresStore(client)
	if err != nil {
		log.Fatal(err)
	}
	store.DeleteAll()
	for _, Product := range products {
		err := store.Insert(Product)
		if err != nil {
			log.Fatal(err)
		}
	}
	return store
}

func (server *Server) initProductService(store domain.ProductStore) *application.ProductService {
	return application.NewProductService(store)
}

func (server *Server) initProductHandler(service *application.ProductService) *api.ProductHandler {
	return api.NewProductHandler(service)
}

func (server *Server) startGrpcServer(productHandler *api.ProductHandler) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", server.config.Port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	inventory.RegisterInventoryServiceServer(grpcServer, productHandler)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}
}
