package api

import (
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	pb "github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/infrastructure/grpc/proto"
)

func mapUser(company *domain.User) *pb.User {
	userPb := &pb.User{
		Id:          company.Id.Hex(),
		CompanyName: company.CompanyName,
		Username:    company.Username,
		Description: company.Description,
		Location:    company.Location,
		Website:     company.Website,
		CompanySize: company.CompanySize,
		Industry:    company.Industry,
	}
	return userPb
}
