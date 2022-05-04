package api

import (
	"context"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/application"
	pb "github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/infrastructure/grpc/proto"
)

type AuthenticationHandler struct {
	pb.UnimplementedCompanyServiceServer
	service *application.AuthenticationService
}

func NewAuthenticationHandler(service *application.AuthenticationService) *AuthenticationHandler {
	return &AuthenticationHandler{
		service: service,
	}
}

func (handler *AuthenticationHandler) Get(ctx context.Context, request *pb.GetRequest) (*pb.GetResponse, error) {
	id := request.Id
	objectId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}
	company, err := handler.service.Get(objectId)
	if err != nil {
		return nil, err
	}
	companyPb := mapUser(company)
	response := &pb.GetResponse{
		Company: companyPb,
	}
	return response, nil
}

func (handler *AuthenticationHandler) GetAll(ctx context.Context, request *pb.GetAllRequest) (*pb.GetAllResponse, error) {
	companies, err := handler.service.GetAll()
	if err != nil {
		return nil, err
	}
	response := &pb.GetAllResponse{
		Companies: []*pb.Company{},
	}
	for _, company := range companies {
		current := mapUser(company)
		response.Companies = append(response.Companies, current)
	}
	return response, nil
}
