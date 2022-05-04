package api

import (
	"context"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/application"
	pb "github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/infrastructure/grpc/proto"
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
	/*id := request.Id
	objectId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}
	company, err := handler.service.Get(objectId)
	if err != nil {
		return nil, err
	}
	companyPb := mapUser(company)
	response := &pb.Token{
		//Company: companyPb,
	}*/
	return nil, nil
}

func (handler *AuthenticationHandler) Register(ctx context.Context, request *pb.RegisterRequest) (*pb.RegisterResponse, error) {
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
