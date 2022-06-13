package api

import (
	"context"
	"errors"
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/application"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/infrastructure/api/validation"
	pb "github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/infrastructure/grpc/proto"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/jwt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/logger"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/util"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/go-playground/validator.v9"
	"time"
)

type AuthenticationHandler struct {
	pb.UnimplementedAuthenticationServiceServer
	service     *application.AuthenticationService
	mailService *application.MailService
	goValidator *util.GoValidator
	logger      *logger.Logger
}

func NewAuthenticationHandler(service *application.AuthenticationService, mailService *application.MailService, goValidator *util.GoValidator, logger *logger.Logger) *AuthenticationHandler {
	return &AuthenticationHandler{
		service:     service,
		mailService: mailService,
		goValidator: goValidator,
		logger:      logger,
	}
}

func (handler *AuthenticationHandler) Login(ctx context.Context, request *pb.LoginRequest) (*pb.Token, error) {
	credentials := mapCredentialsToDomain(request.Credentials)
	token, err := handler.service.Login(credentials)

	if err != nil {
		handler.logger.WarningMessage("User: " + request.Credentials.Username + " | Action: Login with bad credentials")
		handler.logger.ErrorMessage("User: " + request.Credentials.Username + " | Action: Login with bad credentials")
		return nil, status.Error(401, "Bad credentials!")
	}

	handler.logger.InfoMessage("User: " + request.Credentials.Username + " | Action: Login")
	tokenPB := mapTokenToPB(token)
	return tokenPB, nil
}

func (handler *AuthenticationHandler) Register(ctx context.Context, request *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	user := mapUserToDomain(request.User)

	err := handler.goValidator.Validator.Struct(user)
	if err != nil {
		handler.logger.WarningMessage("Action: Register user with invalid data")
		return nil, status.Error(500, err.Error())
	}

	newUser, err := handler.service.Register(user)
	if err != nil {
		handler.logger.ErrorMessage("Action: Register user with username " + request.User.Username)
		return nil, status.Error(400, err.Error())
	}

	response := &pb.RegisterResponse{
		Username: newUser.Username,
	}
	handler.logger.InfoMessage("Action: Registered user " + request.User.Username)
	return response, nil
}

func (handler *AuthenticationHandler) ActivateAccount(ctx context.Context, request *pb.ActivateAccountRequest) (*pb.ActivateAccountResponse, error) {
	code := request.Code

	activatedAccount, err := handler.service.ActivateAccount(code)
	if err != nil {
		handler.logger.ErrorMessage("Action: Activate account " + activatedAccount.Username)
		return nil, status.Error(500, err.Error())
	}

	response := &pb.ActivateAccountResponse{
		ActivatedAccount: &pb.ActivatedAccount{
			Message:  activatedAccount.Message,
			Role:     activatedAccount.Role,
			Username: activatedAccount.Username,
			Email:    activatedAccount.Email,
		},
	}

	handler.logger.InfoMessage("Action: Activate account " + activatedAccount.Username)
	return response, nil
}

func (handler *AuthenticationHandler) ForgotPassword(ctx context.Context, request *pb.ForgotPasswordRequest) (*pb.AuthorizationResponse, error) {
	validate := validator.New()
	err := validate.Var(request.Email, "required,email")
	if err != nil {
		handler.logger.ErrorMessage("Action: Forgot password | Message: Invalid email format " + request.Email)
		return nil, status.Error(400, "Wrong email format!")
	}
	email := request.Email

	resp, err := handler.service.SaveToken(email)
	if err != nil {
		handler.logger.ErrorMessage("Action: Creating forgot password token for " + request.Email)
		return nil, err
	}

	handler.mailService.SendForgotPasswordMail(resp.Token, email)
	response := &pb.AuthorizationResponse{}
	handler.logger.InfoMessage("Action: Send forgot password token on " + request.Email)
	return response, nil
}

func (handler *AuthenticationHandler) ChangePasswordPage(ctx context.Context, request *pb.ChangePasswordPageRequest) (*pb.ChangePasswordPageResponse, error) {
	validate := validator.New()
	err := validate.Var(request.Token, "required")
	if err != nil {
		handler.logger.ErrorMessage("Action: Change password | Message: Token required")
		return nil, status.Error(400, "Token is required!")
	}
	resp, err := handler.service.CheckIfTokenExists(request.Token)
	if err != nil {
		handler.logger.ErrorMessage("Action: Change password | Message: Invalid token")
		return nil, status.Error(400, "Token does not exist!")
	}
	time := time.Now()
	if resp.ExpiringDate.Before(time) {
		handler.logger.ErrorMessage("Action: Change password | Message: Token expired")
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
		handler.logger.ErrorMessage("Action: Change password | Message: Invalid data")
		return nil, status.Error(400, "Wrong input fields!")
	}
	resp, err := handler.service.CheckIfTokenExists(request.ChangePasswordBody.Token)
	if err != nil {
		handler.logger.ErrorMessage("Action: Change password | Message: Invalid token")
		return nil, status.Error(400, "Token does not exist!")
	}
	time := time.Now()
	if resp.ExpiringDate.Before(time) {
		handler.logger.ErrorMessage("Action: Change password | Message: Token expired")
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
		handler.logger.ErrorMessage("User: " + email + " | Action: Passwordless login | Message: User not exists")
		emailErr = errors.New("user does not exist")
		return nil, emailErr
	}

	secureCode, codeError := handler.service.GenerateSecureCode(6)
	if codeError != nil {
		handler.logger.ErrorMessage("User: " + email + " | Action: Passwordless login | Message: Error creating token")
		return nil, codeError
	}

	codeValidationError := validation.ValidateCode(secureCode)
	if codeValidationError != nil {
		handler.logger.ErrorMessage("User: " + email + " | Action: Passwordless login | Message: Invalid token")
		validation.PrintValidationErrors(codeValidationError)
		return nil, codeValidationError
	}

	fmt.Printf("Creating credentials\n")

	hashedCode, hashError := handler.service.HashSecureCode(secureCode)
	if hashError != nil {
		handler.logger.ErrorMessage("User: " + email + " | Action: Passwordless login | Message: Error hashing token")
		return nil, hashError
	}

	credentialsDomain := createPasswordlessCredentials(request.PasswordlessCredentials, hashedCode)

	validationError := validation.ValidatePasswordlessCredentials(credentialsDomain)
	if validationError != nil {
		handler.logger.ErrorMessage("User: " + email + " | Action: Passwordless login | Message: Invalid credentials")
		validation.PrintValidationErrors(validationError)
		return nil, validationError
	}

	_, createError := handler.service.CreatePasswordlessCredentials(credentialsDomain)
	if createError != nil {
		return nil, createError
	}
	fmt.Printf("Created credentials\n")
	fmt.Printf("Sending email\n")

	err := handler.mailService.SendPasswordlessCode(email, secureCode)
	if err != nil {
		handler.logger.ErrorMessage("User: " + email + " | Action: Passwordless login | Message: Error with sending email")
		panic(err)
	}

	response := &pb.GenerateCodeResponse{
		PasswordlessCredentials: &pb.PasswordlessCredentials{
			Code:         secureCode,
			Email:        email,
			ExpiringDate: timestamppb.New(credentialsDomain.ExpiringDate),
		},
	}

	handler.logger.InfoMessage("User: " + email + " | Action: Passwordless login | Message: Token sent")
	return response, nil
}

func (handler *AuthenticationHandler) LoginWithCode(ctx context.Context, request *pb.PasswordlessLoginRequest) (*pb.Token, error) {
	credentials := mapPasswordlessCredentialsToDomain(request.Passwordless)
	validationError := validation.ValidatePasswordlessCredentials(credentials)
	if validationError != nil {
		handler.logger.ErrorMessage("User: " + credentials.Email + " | Action: Passwordless login | Message: Invalid credentials")
		validation.PrintValidationErrors(validationError)
		return nil, validationError
	}

	token, err := handler.service.LoginWithCode(credentials)

	if err != nil {
		handler.logger.ErrorMessage("User: " + credentials.Email + " | Action: Passwordless login | Message: Bad credentials")
		return nil, err
	}

	tokenPB := mapTokenToPB(token)
	handler.logger.InfoMessage("User: " + credentials.Email + " | Action: Passwordless login | Message: Success")
	return tokenPB, nil
}
func (handler *AuthenticationHandler) SendApiToken(ctx context.Context, request *pb.AuthorizationResponse) (*pb.AuthorizationResponse, error) {
	username, err := jwt.ExtractUsernameFromToken(ctx)
	fmt.Printf("Sending token started %s\n", username)
	if err != nil {
		handler.logger.ErrorMessage("User: " + username + " | Action: Send Api token login | Message: Wrong username")
		return nil, status.Error(400, "Wrong username in token!")
	}
	err = handler.service.SendApiToken(username)
	if err != nil {
		handler.logger.ErrorMessage("User: " + username + " | Action: Send Api token login")
		return nil, err
	}

	handler.logger.InfoMessage("User: " + username + " | Action: Send Api token login")
	response := &pb.AuthorizationResponse{}
	return response, nil
}

func (handler *AuthenticationHandler) RegisterToGoogleAuthenticatior(ctx context.Context, request *pb.AuthorizationResponse) (*pb.QRImageResponse, error) {
	username, err := jwt.ExtractUsernameFromToken(ctx)
	fmt.Println("Request for qr started ", username)
	if err != nil {
		handler.logger.ErrorMessage("User: " + username + " | Action: Register to Google Auth | Message: Wrong username")
		return nil, status.Error(400, "Wrong username in token!")
	}
	qr, err := handler.service.RegisterToGoogleAuthenticatior(username)
	if err != nil {
		handler.logger.ErrorMessage("User: " + username + " | Action: Register to Google Auth")
		return nil, err
	}
	response := &pb.QRImageResponse{
		Image: qr,
	}

	handler.logger.InfoMessage("User: " + username + " | Action: Register to Google Auth")
	return response, nil
}
func (handler *AuthenticationHandler) CheckMFACode(ctx context.Context, request *pb.ChangePasswordPageRequest) (*pb.AuthorizationResponse, error) {
	username, err := jwt.ExtractUsernameFromToken(ctx)
	fmt.Println("Request for qr started ", username)
	if err != nil {
		handler.logger.ErrorMessage("User: " + username + " | Action: Check MFA Code  | Message: Wrong username")
		return nil, status.Error(400, "Wrong username in token!")
	}
	err = handler.service.CheckMFACode(username, request.Token)
	if err != nil {
		handler.logger.ErrorMessage("User: " + username + " | Action: Check MFA Code  | Message: Wrong input")
		return nil, status.Error(400, "Wrong code input!")
	}
	response := &pb.AuthorizationResponse{}

	handler.logger.InfoMessage("User: " + username + " | Action: Check MFA Code")
	return response, nil
}

func (handler *AuthenticationHandler) CheckMFACodeUnauthorized(ctx context.Context, request *pb.MFALoginRequest) (*pb.Token, error) {

	token, err := handler.service.CheckMFACodeUnauthorized(request.Username, request.Token)
	if err != nil {
		handler.logger.ErrorMessage("User: " + request.Username + " | Action: Check MFA Code | Message: Unauthorized")
		handler.logger.WarningMessage("User: " + request.Username + " | Action: Check MFA Code | Message: Unauthorized")
		return nil, err
	}
	tokenPB := mapTokenToPB(token)
	return tokenPB, nil
}

func (handler *AuthenticationHandler) ResetSetMFACode(ctx context.Context, request *pb.AuthorizationResponse) (*pb.AuthorizationResponse, error) {
	username, _ := jwt.ExtractUsernameFromToken(ctx)
	handler.service.ResetSetMFACode(username)
	handler.logger.InfoMessage("User: " + username + " | Action: Reset set MFA Code")
	response := &pb.AuthorizationResponse{}
	return response, nil
}

func (handler *AuthenticationHandler) CheckIfMFAActive(ctx context.Context, request *pb.AuthorizationResponse) (*pb.CheckIfMFAActiveResponse, error) {
	username, _ := jwt.ExtractUsernameFromToken(ctx)
	fmt.Println("Username is :", username)
	resp := handler.service.CheckIfMFAActive(username)
	response := &pb.CheckIfMFAActiveResponse{
		IsActive: resp,
	}
	return response, nil
}

func (handler *AuthenticationHandler) CheckIfUserExist(ctx context.Context, request *pb.CheckIfUserExistsRequest) (*pb.CheckIfUserExistsResponse, error) {
	resp := handler.service.CheckIfUserExists(request.Username)
	response := &pb.CheckIfUserExistsResponse{
		Exists: resp,
	}
	return response, nil
}
