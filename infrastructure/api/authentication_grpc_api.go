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
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/tracer"
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
	span := tracer.StartSpanFromContext(ctx, "Login")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	credentials := mapCredentialsToDomain(request.Credentials)
	token, err := handler.service.Login(ctx, credentials)

	if err != nil {
		handler.logger.WarningMessage("User: " + request.Credentials.Username + " | Action: L BC")
		handler.logger.ErrorMessage("User: " + request.Credentials.Username + " | Action: L BC")
		return nil, status.Error(401, "Bad credentials!")
	}

	handler.logger.InfoMessage("User: " + request.Credentials.Username + " | Action: L")
	tokenPB := mapTokenToPB(token)
	return tokenPB, nil
}

func (handler *AuthenticationHandler) Register(ctx context.Context, request *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	span := tracer.StartSpanFromContext(ctx, "Register")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	user := mapUserToDomain(request.User)

	err := handler.goValidator.Validator.Struct(user)
	if err != nil {
		handler.logger.WarningMessage("Action: RUID")
		return nil, status.Error(500, err.Error())
	}

	newUser, err := handler.service.Register(ctx, user)
	if err != nil {
		handler.logger.ErrorMessage("Action: RU " + request.User.Username)
		return nil, status.Error(400, err.Error())
	}

	response := &pb.RegisterResponse{
		Username: newUser.Username,
	}
	handler.logger.InfoMessage("Action: RU " + request.User.Username)
	return response, nil
}

func (handler *AuthenticationHandler) ActivateAccount(ctx context.Context, request *pb.ActivateAccountRequest) (*pb.ActivateAccountResponse, error) {
	span := tracer.StartSpanFromContext(ctx, "ActivateAccount")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	code := request.Code

	activatedAccount, err := handler.service.ActivateAccount(ctx, code)
	if err != nil {
		handler.logger.ErrorMessage("Action: AA " + activatedAccount.Username)
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

	handler.logger.InfoMessage("Action: AA " + activatedAccount.Username)
	return response, nil
}

func (handler *AuthenticationHandler) ForgotPassword(ctx context.Context, request *pb.ForgotPasswordRequest) (*pb.AuthorizationResponse, error) {
	span := tracer.StartSpanFromContext(ctx, "ForgotPassword")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	validate := validator.New()
	err := validate.Var(request.Email, "required,email")
	if err != nil {
		handler.logger.ErrorMessage("Action: FP | IE " + request.Email)
		return nil, status.Error(400, "Wrong email format!")
	}
	email := request.Email

	resp, err := handler.service.SaveToken(ctx, email)
	if err != nil {
		handler.logger.ErrorMessage("Action: CFP  " + request.Email)
		return nil, err
	}

	handler.mailService.SendForgotPasswordMail(ctx, resp.Token, email)
	response := &pb.AuthorizationResponse{}
	handler.logger.InfoMessage("Action: SFPT " + request.Email)
	return response, nil
}

func (handler *AuthenticationHandler) ChangePasswordPage(ctx context.Context, request *pb.ChangePasswordPageRequest) (*pb.ChangePasswordPageResponse, error) {
	span := tracer.StartSpanFromContext(ctx, "ChangePasswordPage")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	validate := validator.New()
	err := validate.Var(request.Token, "required")
	if err != nil {
		handler.logger.ErrorMessage("Action: CP | TR")
		return nil, status.Error(400, "Token is required!")
	}
	resp, err := handler.service.CheckIfTokenExists(ctx, request.Token)
	if err != nil {
		handler.logger.ErrorMessage("Action: CP | IT")
		return nil, status.Error(400, "Token does not exist!")
	}
	time := time.Now()
	if resp.ExpiringDate.Before(time) {
		handler.logger.ErrorMessage("Action: CP | TE")
		return nil, status.Error(400, "Token has expired")
	}
	response := &pb.ChangePasswordPageResponse{
		Token: resp.Token,
	}
	return response, nil
}

func (handler *AuthenticationHandler) ChangePassword(ctx context.Context, request *pb.ChangePasswordRequest) (*pb.AuthorizationResponse, error) {
	span := tracer.StartSpanFromContext(ctx, "ChangePassword")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	dto := mapChangePasswordPbToDto(request.ChangePasswordBody)
	validate := validator.New()
	err := validate.Struct(dto)
	if err != nil {
		handler.logger.ErrorMessage("Action: CP | II")
		return nil, status.Error(400, "Wrong input fields!")
	}
	resp, err := handler.service.CheckIfTokenExists(ctx, request.ChangePasswordBody.Token)
	if err != nil {
		handler.logger.ErrorMessage("Action: CP | IT")
		return nil, status.Error(400, "Token does not exist!")
	}
	time := time.Now()
	if resp.ExpiringDate.Before(time) {
		handler.logger.ErrorMessage("Action: CP | TE")
		return nil, status.Error(400, "Token has expired")
	}
	err = handler.service.ChangePassword(ctx, dto, resp)
	if err != nil {
		return nil, err
	}
	response := &pb.AuthorizationResponse{}
	return response, nil
}

func (handler *AuthenticationHandler) GenerateCode(ctx context.Context, request *pb.GenerateCodeRequest) (*pb.GenerateCodeResponse, error) {
	span := tracer.StartSpanFromContext(ctx, "GenerateCode")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	email := request.PasswordlessCredentials.GetEmail()
	user, emailErr := handler.service.GetByEmail(ctx, email)
	if emailErr != nil || user == nil {
		handler.logger.ErrorMessage("User: " + email + " | Action: PL | NE")
		emailErr = errors.New("user does not exist")
		return nil, emailErr
	}

	secureCode, codeError := handler.service.GenerateSecureCode(ctx, 6)
	if codeError != nil {
		handler.logger.ErrorMessage("User: " + email + " | Action: PL | CT")
		return nil, codeError
	}

	codeValidationError := validation.ValidateCode(secureCode)
	if codeValidationError != nil {
		handler.logger.ErrorMessage("User: " + email + " | Action: PL | IT")
		validation.PrintValidationErrors(codeValidationError)
		return nil, codeValidationError
	}

	fmt.Printf("Creating credentials\n")

	hashedCode, hashError := handler.service.HashSecureCode(ctx, secureCode)
	if hashError != nil {
		handler.logger.ErrorMessage("User: " + email + " | Action: PL | HT")
		return nil, hashError
	}

	credentialsDomain := createPasswordlessCredentials(request.PasswordlessCredentials, hashedCode)

	validationError := validation.ValidatePasswordlessCredentials(credentialsDomain)
	if validationError != nil {
		handler.logger.ErrorMessage("User: " + email + " | Action: PL | IC")
		validation.PrintValidationErrors(validationError)
		return nil, validationError
	}

	_, createError := handler.service.CreatePasswordlessCredentials(ctx, credentialsDomain)
	if createError != nil {
		return nil, createError
	}
	fmt.Printf("Created credentials\n")
	fmt.Printf("Sending email\n")

	err := handler.mailService.SendPasswordlessCode(ctx, email, secureCode)
	if err != nil {
		handler.logger.ErrorMessage("User: " + email + " | Action: PL | Message: SM")
		panic(err)
	}

	response := &pb.GenerateCodeResponse{
		PasswordlessCredentials: &pb.PasswordlessCredentials{
			Code:         secureCode,
			Email:        email,
			ExpiringDate: timestamppb.New(credentialsDomain.ExpiringDate),
		},
	}

	handler.logger.InfoMessage("User: " + email + " | Action: PL | TS")
	return response, nil
}

func (handler *AuthenticationHandler) LoginWithCode(ctx context.Context, request *pb.PasswordlessLoginRequest) (*pb.Token, error) {
	span := tracer.StartSpanFromContext(ctx, "LoginWithCode")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	credentials := mapPasswordlessCredentialsToDomain(request.Passwordless)
	validationError := validation.ValidatePasswordlessCredentials(credentials)
	if validationError != nil {
		handler.logger.ErrorMessage("User: " + credentials.Email + " | Action: PL | IC")
		validation.PrintValidationErrors(validationError)
		return nil, validationError
	}

	token, err := handler.service.LoginWithCode(ctx, credentials)

	if err != nil {
		handler.logger.ErrorMessage("User: " + credentials.Email + " | Action: PL | IC")
		return nil, err
	}

	tokenPB := mapTokenToPB(token)
	handler.logger.InfoMessage("User: " + credentials.Email + " | Action: PL")
	return tokenPB, nil
}
func (handler *AuthenticationHandler) SendApiToken(ctx context.Context, request *pb.AuthorizationResponse) (*pb.AuthorizationResponse, error) {
	span := tracer.StartSpanFromContext(ctx, "SendApiToken")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	username, err := jwt.ExtractUsernameFromToken(ctx)
	fmt.Printf("Sending token started %s\n", username)
	if err != nil {
		handler.logger.ErrorMessage("User: " + username + " | Action: SATL | u")
		return nil, status.Error(400, "Wrong username in token!")
	}
	err = handler.service.SendApiToken(ctx, username)
	if err != nil {
		handler.logger.ErrorMessage("User: " + username + " | Action: SATL")
		return nil, err
	}

	handler.logger.InfoMessage("User: " + username + " | Action: SATL")
	response := &pb.AuthorizationResponse{}
	return response, nil
}

func (handler *AuthenticationHandler) RegisterToGoogleAuthenticatior(ctx context.Context, request *pb.AuthorizationResponse) (*pb.QRImageResponse, error) {
	span := tracer.StartSpanFromContext(ctx, "RegisterToGoogleAuthenticatior")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	username, err := jwt.ExtractUsernameFromToken(ctx)
	fmt.Println("Request for qr started ", username)
	if err != nil {
		handler.logger.ErrorMessage("User: " + username + " | Action: RGAuth")
		return nil, status.Error(400, "Wrong username in token!")
	}
	qr, err := handler.service.RegisterToGoogleAuthenticatior(ctx, username)
	if err != nil {
		handler.logger.ErrorMessage("User: " + username + " | Action: RGAuth")
		return nil, err
	}
	response := &pb.QRImageResponse{
		Image: qr,
	}

	handler.logger.InfoMessage("User: " + username + " | Action: RGAuth")
	return response, nil
}
func (handler *AuthenticationHandler) CheckMFACode(ctx context.Context, request *pb.ChangePasswordPageRequest) (*pb.AuthorizationResponse, error) {
	span := tracer.StartSpanFromContext(ctx, "CheckMFACode")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	username, err := jwt.ExtractUsernameFromToken(ctx)
	fmt.Println("Request for qr started ", username)
	if err != nil {
		handler.logger.ErrorMessage("User: " + username + " | Action: CMFAC")
		return nil, status.Error(400, "Wrong username in token!")
	}
	err = handler.service.CheckMFACode(ctx, username, request.Token)
	if err != nil {
		handler.logger.ErrorMessage("User: " + username + " | Action: CMFAC")
		return nil, status.Error(400, "Wrong code input!")
	}
	response := &pb.AuthorizationResponse{}

	handler.logger.InfoMessage("User: " + username + " | Action: CMFAC")
	return response, nil
}

func (handler *AuthenticationHandler) CheckMFACodeUnauthorized(ctx context.Context, request *pb.MFALoginRequest) (*pb.Token, error) {
	span := tracer.StartSpanFromContext(ctx, "CheckMFACodeUnauthorized")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	token, err := handler.service.CheckMFACodeUnauthorized(ctx, request.Username, request.Token)
	if err != nil {
		handler.logger.ErrorMessage("User: " + request.Username + " | Action: CMFAC | 403")
		handler.logger.WarningMessage("User: " + request.Username + " | Action: CMFAC | 403")
		return nil, err
	}
	tokenPB := mapTokenToPB(token)
	return tokenPB, nil
}

func (handler *AuthenticationHandler) ResetSetMFACode(ctx context.Context, request *pb.AuthorizationResponse) (*pb.AuthorizationResponse, error) {
	span := tracer.StartSpanFromContext(ctx, "ResetSetMFACode")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	username, _ := jwt.ExtractUsernameFromToken(ctx)
	handler.service.ResetSetMFACode(ctx, username)
	handler.logger.InfoMessage("User: " + username + " | Action: RSMFAC")
	response := &pb.AuthorizationResponse{}
	return response, nil
}

func (handler *AuthenticationHandler) CheckIfMFAActive(ctx context.Context, request *pb.AuthorizationResponse) (*pb.CheckIfMFAActiveResponse, error) {
	span := tracer.StartSpanFromContext(ctx, "CheckIfMFAActive")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	username, _ := jwt.ExtractUsernameFromToken(ctx)
	fmt.Println("Username is :", username)
	resp := handler.service.CheckIfMFAActive(ctx, username)
	response := &pb.CheckIfMFAActiveResponse{
		IsActive: resp,
	}
	return response, nil
}

func (handler *AuthenticationHandler) CheckIfUserExist(ctx context.Context, request *pb.CheckIfUserExistsRequest) (*pb.CheckIfUserExistsResponse, error) {
	span := tracer.StartSpanFromContext(ctx, "CheckIfUserExist")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	resp := handler.service.CheckIfUserExists(ctx, request.Username)
	response := &pb.CheckIfUserExistsResponse{
		Exists: resp,
	}
	return response, nil
}
