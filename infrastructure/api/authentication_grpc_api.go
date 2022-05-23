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
	service     *application.AuthenticationService
	mailService *application.MailService
}

func NewAuthenticationHandler(service *application.AuthenticationService, mailService *application.MailService) *AuthenticationHandler {
	return &AuthenticationHandler{
		service:     service,
		mailService: mailService,
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

func (handler *AuthenticationHandler) ForgotPassword(ctx context.Context, request *pb.ForgotPasswordRequest) (*pb.AuthorizationResponse, error) {
	email := request.Email
	resp, err := handler.service.SaveToken(email)
	fmt.Printf("Api token,%s\n", resp.Token)
	if err != nil {
		fmt.Println("Api error")
		return nil, err
	}
	fmt.Printf("Sending email\n")
	handler.mailService.SendForgotPasswordMail(resp.Token, email)
	response := &pb.AuthorizationResponse{}
	return response, nil
}

func (handler *AuthenticationHandler) GenerateCode(ctx context.Context, request *pb.GenerateCodeRequest) (*pb.GenerateCodeResponse, error) {
	fmt.Printf("Sending email\n")
	email := request.PasswordlessCredentials.GetEmail()
	
	handler.mailService.SendPasswordlessCode(email)
	response := &pb.GenerateCodeResponse{}
	return response, nil
}

func (handler *AuthenticationHandler) IsAuthorized(ctx context.Context, request *pb.AuthorizationRequest) (*pb.AuthorizationResponse, error) {

	return nil, nil
}
