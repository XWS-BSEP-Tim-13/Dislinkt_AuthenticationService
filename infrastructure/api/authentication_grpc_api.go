package api

import (
	"context"
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/application"
	pb "github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/infrastructure/grpc/proto"
	"google.golang.org/grpc/status"
)

type AuthenticationHandler struct {
	pb.UnimplementedAuthenticationServiceServer
	service *application.AuthenticationService
}

func NewAuthenticationHandler(service *application.AuthenticationService) *AuthenticationHandler {
	return &AuthenticationHandler{
		service: service,
	}
}

func (handler *AuthenticationHandler) Login(ctx context.Context, request *pb.LoginRequest) (*pb.Token, error) {
	credentials := mapCredentialsToDomain(request.Credentials)
	token, err := handler.service.Login(credentials)

	if err != nil {
		return nil, status.Error(401, "Bad credentials!")
	}

	tokenPB := mapTokenToPB(token)
	return tokenPB, nil
}

func (handler *AuthenticationHandler) Register(ctx context.Context, request *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	fmt.Println((*request).User)
	user := mapUserToDomain(request.User)
	fmt.Println(user)
	newUser, err := handler.service.Register(user)
	if err != nil {
		return nil, status.Error(400, "Username already exists!")
	}

	response := &pb.RegisterResponse{
		Username: newUser.Username,
	}
	return response, nil
}

func (handler *AuthenticationHandler) IsAuthorized(ctx context.Context, request *pb.AuthorizationRequest) (*pb.AuthorizationResponse, error) {
	//companies, err := handler.service.GetAll()
	//if err != nil {
	//	return nil, err
	//}
	//response := &pb.GetAllResponse{
	//	Companies: []*pb.Company{},
	//}
	//for _, company := range companies {
	//	current := mapUser(company)
	//	response.Companies = append(response.Companies, current)
	//}
	return nil, nil
}
