package api

import (
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	pb "github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/infrastructure/grpc/proto"
)

func mapUser(user *domain.User) *pb.User {
	userPb := &pb.User{
		Username: user.Username,
		Password: user.Password,
		Role:     user.Role,
	}
	return userPb
}

func mapToken(token *domain.Token) *pb.Token {
	tokenPb := &pb.Token{
		Role:     token.Role,
		Username: token.Username,
		Token:    token.TokenString,
	}
	return tokenPb
}
