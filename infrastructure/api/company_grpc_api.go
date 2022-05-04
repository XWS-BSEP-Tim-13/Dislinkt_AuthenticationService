package api

import (
	"context"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_CompanyService/application"
	pb "github.com/XWS-BSEP-Tim-13/Dislinkt_CompanyService/infrastructure/grpc/proto"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type CompanyHandler struct {
	pb.UnimplementedCompanyServiceServer
	service *application.CompanyService
}

func NewCompanyHandler(service *application.CompanyService) *CompanyHandler {
	return &CompanyHandler{
		service: service,
	}
}

func (handler *CompanyHandler) Get(ctx context.Context, request *pb.GetRequest) (*pb.GetResponse, error) {
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

func (handler *CompanyHandler) GetAll(ctx context.Context, request *pb.GetAllRequest) (*pb.GetAllResponse, error) {
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
