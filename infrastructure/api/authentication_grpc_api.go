package api

import (
	"context"
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/application"
	pb "github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/infrastructure/grpc/proto"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/util"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type AuthenticationHandler struct {
	pb.UnimplementedAuthenticationServiceServer
	service     *application.AuthenticationService
	mailService *application.MailService
	goValidator *util.GoValidator
}

func NewAuthenticationHandler(service *application.AuthenticationService, mailService *application.MailService, goValidator *util.GoValidator) *AuthenticationHandler {
	return &AuthenticationHandler{
		service:     service,
		mailService: mailService,
		goValidator: goValidator,
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

	err := handler.goValidator.Validator.Struct(user)
	if err != nil {
		return nil, status.Error(500, err.Error())
	}

	newUser, err := handler.service.Register(user)
	if err != nil {
		return nil, status.Error(400, err.Error())
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
	email := request.PasswordlessCredentials.GetEmail()
	user, emailErr := handler.service.GetByEmail(email)
	if emailErr != nil || user == nil {
		fmt.Println("User does not exist")
		return nil, emailErr
	}

	secureCode, codeError := handler.service.GenerateSecureCode(6)
	if codeError != nil {
		return nil, codeError
	}

	fmt.Printf("Creating credentials\n")
	credentialsDomain := createPasswordlessCredentials(request.PasswordlessCredentials, secureCode)
	_, createError := handler.service.CreatePasswordlessCredentials(credentialsDomain)
	if createError != nil {
		return nil, createError
	}
	fmt.Printf("Created credentials\n")
	fmt.Printf("Sending email\n")

	err := handler.mailService.SendPasswordlessCode(email, secureCode)
	if err != nil {
		panic(err)
	}

	response := &pb.GenerateCodeResponse{
		PasswordlessCredentials: &pb.PasswordlessCredentials{
			Code:         secureCode,
			Email:        email,
			ExpiringDate: timestamppb.New(credentialsDomain.ExpiringDate),
		},
	}
	return response, nil
}

func (handler *AuthenticationHandler) IsAuthorized(ctx context.Context, request *pb.AuthorizationRequest) (*pb.AuthorizationResponse, error) {

	return nil, nil
}
