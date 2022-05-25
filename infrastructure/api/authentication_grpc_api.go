package api

import (
	"context"
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/application"
	pb "github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/infrastructure/grpc/proto"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/go-playground/validator.v9"
	"time"
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
	fmt.Printf("Login request started %s, %s\n", request.Credentials.Username, request.Credentials.Password)
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
	fmt.Printf("Email : %s\n", request.Email)
	validate := validator.New()
	err := validate.Var(request.Email, "required,email")
	if err != nil {
		return nil, status.Error(400, "Wrong email format!")
	}
	email := request.Email

	resp, err := handler.service.SaveToken(email)
	fmt.Printf("Api token,%s\n", resp.Token)
	if err != nil {
		return nil, err
	}
	handler.mailService.SendForgotPasswordMail(resp.Token, email)
	response := &pb.AuthorizationResponse{}
	return response, nil
}

func (handler *AuthenticationHandler) ChangePasswordPage(ctx context.Context, request *pb.ChangePasswordPageRequest) (*pb.ChangePasswordPageResponse, error) {
	validate := validator.New()
	err := validate.Var(request.Token, "required")
	if err != nil {
		return nil, status.Error(400, "Token is required!")
	}
	resp, err := handler.service.CheckIfTokenExists(request.Token)
	if err != nil {
		return nil, status.Error(400, "Token does not exist!")
	}
	time := time.Now()
	if resp.ExpiringDate.Before(time) {
		return nil, status.Error(400, "Token has expired")
	}
	response := &pb.ChangePasswordPageResponse{
		Token: resp.Token,
	}
	return response, nil
}

func (handler *AuthenticationHandler) ChangePassword(ctx context.Context, request *pb.ChangePasswordRequest) (*pb.AuthorizationResponse, error) {
	dto := mapChangePasswordPbToDto(request.ChangePasswordBody)
	validate := validator.New()
	err := validate.Struct(dto)
	if err != nil {
		return nil, status.Error(400, "Wrong input fields!")
	}
	resp, err := handler.service.CheckIfTokenExists(request.ChangePasswordBody.Token)
	if err != nil {
		return nil, status.Error(400, "Token does not exist!")
	}
	time := time.Now()
	if resp.ExpiringDate.Before(time) {
		return nil, status.Error(400, "Token has expired")
	}
	err = handler.service.ChangePassword(dto, resp)
	if err != nil {
		return nil, err
	}
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

	hashedCode, hashError := handler.service.HashSecureCode(secureCode)
	if hashError != nil {
		return nil, hashError
	}

	credentialsDomain := createPasswordlessCredentials(request.PasswordlessCredentials, hashedCode)
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

func (handler *AuthenticationHandler) LoginWithCode(ctx context.Context, request *pb.PasswordlessLoginRequest) (*pb.Token, error) {
	credentials := mapPasswordlessCredentialsToDomain(request.Passwordless)
	token, err := handler.service.LoginWithCode(credentials)

	if err != nil {
		return nil, err
	}

	tokenPB := mapTokenToPB(token)
	return tokenPB, nil
}

func (handler *AuthenticationHandler) IsAuthorized(ctx context.Context, request *pb.AuthorizationRequest) (*pb.AuthorizationResponse, error) {

	return nil, nil
}
