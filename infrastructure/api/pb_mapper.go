package api

import (
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	pb "github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/infrastructure/grpc/proto"
	"time"
)

func mapUserToPB(user *domain.User) *pb.User {
	userPb := &pb.User{
		Username: user.Username,
		Password: user.Password,
		Role:     user.Role,
	}
	return userPb
}

func mapUserToDomain(user *pb.User) *domain.User {
	userDomain := &domain.User{
		Username: (*user).Username,
		Password: (*user).Password,
		Role:     (*user).Role,
		Email:    (*user).Email,
	}
	return userDomain
}

func mapTokenToPB(token *domain.Token) *pb.Token {
	tokenPb := &pb.Token{
		Role:     token.Role,
		Username: token.Username,
		Token:    token.TokenString,
	}
	return tokenPb
}

func mapCredentialsToDomain(credentials *pb.Credentials) *domain.Credentials {
	credentialsDomain := &domain.Credentials{
		Username: (*credentials).Username,
		Password: (*credentials).Password,
	}
	return credentialsDomain
}

func createPasswordlessCredentials(passwordless *pb.PasswordlessCredentialsEmail, code string) *domain.PasswordlessCredentials {
	expires := time.Now().Local().Add(time.Minute * 15)

	credentialsDomain := &domain.PasswordlessCredentials{
		Email:        (*passwordless).Email,
		Code:         code,
		ExpiringDate: expires,
	}

	return credentialsDomain
}
