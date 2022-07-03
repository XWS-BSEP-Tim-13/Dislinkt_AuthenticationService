package application

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/logger"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/tracer"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/dgryski/dgoogauth"
	"github.com/google/uuid"
	"image/png"
	"runtime"
	"strings"
	"time"
)

type AuthenticationService struct {
	store             domain.UserStore
	jwtManager        JwtManager
	tokenStore        domain.ForgotPasswordTokenStore
	passwordlessStore domain.PasswordlessStore
	verificationStore domain.VerificationStore
	mailService       *MailService
	activemqService   ActiveMQ
	logger            *logger.Logger
}

func NewAuthenticationService(store domain.UserStore, tokenStore domain.ForgotPasswordTokenStore, passwordlessStore domain.PasswordlessStore, verificationStore domain.VerificationStore, mailService *MailService, activemqService ActiveMQ, logger *logger.Logger) *AuthenticationService {
	return &AuthenticationService{
		store:             store,
		jwtManager:        *NewJwtManager(),
		tokenStore:        tokenStore,
		passwordlessStore: passwordlessStore,
		activemqService:   activemqService,
		verificationStore: verificationStore,
		mailService:       mailService,
		logger:            logger,
	}
}

func (service *AuthenticationService) Login(ctx context.Context, credentials *domain.Credentials) (*domain.Token, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "Login")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	dbUser, _ := service.store.GetActiveByUsername(ctx, (*credentials).Username)
	if (*dbUser).Username == "" {
		fmt.Println("Mail erorrr")
		err := errors.New("bad credentials")
		return nil, err
	}

	isPasswordCorrect := service.jwtManager.CheckPasswordHash(ctx, (*credentials).Password, (*dbUser).Password)
	if !isPasswordCorrect {
		fmt.Println("Hash erorrr")
		err := errors.New("bad credentials")
		return nil, err
	}

	validToken, err := service.jwtManager.GenerateJWT(ctx, (*dbUser).Username, (*dbUser).Role)
	if err != nil {
		fmt.Println("Jwt erorrr")
		err := errors.New("failed to generate token")
		return nil, err
	}

	var token domain.Token
	if dbUser.MFASecret != "" {
		token.Username = (*dbUser).Username
		token.Role = ""
		token.TokenString = ""
	} else {
		token.Username = (*dbUser).Username
		token.Role = (*dbUser).Role
		token.TokenString = validToken
	}
	fmt.Println("Passed")
	return &token, nil
}

func (service *AuthenticationService) Register(ctx context.Context, user *domain.User) (*domain.User, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "Register")
	defer span.Finish()

	dbUser, _ := service.store.GetByUsername(ctx, (*user).Username)
	if (*dbUser).Username != "" {
		err := errors.New("username already exists")
		return nil, err
	}

	dbUser, _ = service.store.GetByEmail(ctx, (*user).Email)
	if (*dbUser).Username != "" {
		err := errors.New("email already exists")
		return nil, err
	}

	var err error
	(*user).Password, err = service.jwtManager.GenerateHashPassword(ctx, (*user).Password)
	if err != nil {
		err := errors.New("error in hashing password")
		return nil, err
	}

	(*user).IsActive = false
	newUser, err := service.store.Create(ctx, user)

	if err != nil {
		err := errors.New("error in saving user data")
		return nil, err
	}

	verificationData, err := service.verificationStore.Create(ctx, &domain.VerificationData{
		Code:      uuid.New().String(),
		Email:     (*newUser).Email,
		ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(1)),
		CodeUsed:  false,
	})
	if err != nil {
		err := errors.New("error in saving verification data")
		return nil, err
	}

	err = service.mailService.SendVerificationEmail(ctx, (*verificationData).Email, (*verificationData).Code)
	if err != nil {
		err := errors.New("error sending e-mail")
		return nil, err
	}

	return newUser, nil
}

func (service *AuthenticationService) ActivateAccount(ctx context.Context, code string) (*domain.ActivatedAccount, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "ActivateAccount")
	defer span.Finish()

	verificationData, err := service.verificationStore.GetByCode(ctx, code)
	if err != nil {
		err := errors.New("error reading verification data")
		return nil, err
	}

	user, err := service.store.GetByEmail(ctx, verificationData.Email)
	if err != nil {
		err := errors.New("error reading user data")
		return nil, err
	}

	if verificationData.CodeUsed == true {
		activatedAccount := &domain.ActivatedAccount{
			Message:  "Activation code already used!",
			Role:     user.Role,
			Email:    user.Email,
			Username: user.Username,
		}
		return activatedAccount, nil
	}

	if verificationData.ExpiresAt.Before(time.Now()) {
		activatedAccount := &domain.ActivatedAccount{
			Message:  "Activation email expired!",
			Role:     user.Role,
			Email:    user.Email,
			Username: user.Username,
		}
		return activatedAccount, nil
	}

	err = service.store.UpdateIsActive(ctx, user)
	if err != nil {
		err := errors.New("error activating account")
		return nil, err
	}

	err = service.verificationStore.UpdateUsedData(ctx, verificationData)
	if err != nil {
		err := errors.New("error updating verification data")
		return nil, err
	}

	activatedAccount := &domain.ActivatedAccount{
		Message:  "Account successfully activated!",
		Role:     user.Role,
		Email:    user.Email,
		Username: user.Username,
	}

	return activatedAccount, nil
}

func (service *AuthenticationService) SaveToken(ctx context.Context, email string) (*domain.ForgotPasswordToken, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "SaveToken")
	defer span.Finish()

	var request = domain.ForgotPasswordToken{
		Email:        email,
		Token:        uuid.New().String(),
		ExpiringDate: time.Now().Local().Add(time.Hour * time.Duration(4)),
	}
	return service.tokenStore.Create(ctx, &request)
}

func (service *AuthenticationService) CheckIfTokenExists(ctx context.Context, token string) (*domain.ForgotPasswordToken, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "CheckIfTokenExists")
	defer span.Finish()

	return service.tokenStore.GetByToken(ctx, token)
}

func (service *AuthenticationService) ChangePassword(ctx context.Context, dto *domain.ChangePasswordDto, tokenObj *domain.ForgotPasswordToken) error {
	span := tracer.StartSpanFromContextMetadata(ctx, "ChangePassword")
	defer span.Finish()

	fmt.Printf("Changing password%s, %s \n", dto.Password, dto.ConfirmPassword)
	if dto.Password != dto.ConfirmPassword {
		err := errors.New("passwords do not match")
		return err
	}
	resp, err := service.store.GetByEmail(ctx, tokenObj.Email)
	if err != nil {
		return err
	}
	fmt.Printf("By email: %s\n", resp.Username)
	resp.Password, err = service.jwtManager.GenerateHashPassword(ctx, dto.Password)
	if err != nil {
		fmt.Printf("Error while generating password! \n")
		return err
	}
	err = service.store.UpdatePassword(ctx, resp)
	if err != nil {
		fmt.Printf("Error while changing password! \n")
		return err
	}
	service.tokenStore.Delete(ctx, tokenObj.ID)
	return nil
}

func (service *AuthenticationService) IsAuthorized(ctx context.Context, token *domain.Token) {
	span := tracer.StartSpanFromContextMetadata(ctx, "IsAuthorized")
	defer span.Finish()

	//service.store.Create()
}

func (service *AuthenticationService) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "GetByEmail")
	defer span.Finish()

	user, err := service.store.GetActiveByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (service *AuthenticationService) CreatePasswordlessCredentials(ctx context.Context, credentials *domain.PasswordlessCredentials) (*domain.PasswordlessCredentials, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "CreatePasswordlessCredentials")
	defer span.Finish()

	newCredentials, err := service.passwordlessStore.Create(ctx, credentials)
	return newCredentials, err
}

func (service *AuthenticationService) GenerateSecureCode(ctx context.Context, length int) (string, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "GenerateSecureCode")
	defer span.Finish()

	otpChars := "1234567890"
	buffer := make([]byte, length)
	_, err := rand.Read(buffer)
	if err != nil {
		return "", err
	}

	otpCharsLength := len(otpChars)
	for i := 0; i < length; i++ {
		buffer[i] = otpChars[int(buffer[i])%otpCharsLength]
	}

	return string(buffer), nil
}

func (service *AuthenticationService) HashSecureCode(ctx context.Context, code string) (string, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "HashSecureCode")
	defer span.Finish()

	hashed, err := service.jwtManager.GenerateHashPassword(ctx, code)
	return hashed, err
}

func (service *AuthenticationService) SendApiToken(ctx context.Context, username string) error {
	span := tracer.StartSpanFromContextMetadata(ctx, "SendApiToken")
	defer span.Finish()

	user, err := service.store.GetByUsername(ctx, username)
	if err != nil {
		return errors.New("user not found")
	}
	token, err := service.jwtManager.GenerateJWTWithEmail(ctx, user.Email, user.Role)
	fmt.Printf("Token generated %s\n", token)
	if err != nil {
		return errors.New("error while creating token")
	}
	service.activemqService.Send(ctx, token)
	return nil
}

func (service *AuthenticationService) CheckIfUserExists(ctx context.Context, email string) bool {
	span := tracer.StartSpanFromContextMetadata(ctx, "CheckIfUserExists")
	defer span.Finish()

	_, err := service.store.GetByEmail(ctx, email)
	if err != nil {
		return false
	}

	return true
}

func (service *AuthenticationService) ReceiveJobOffer(ctx context.Context) {
	span := tracer.StartSpanFromContextMetadata(ctx, "ReceiveJobOffer")
	defer span.Finish()

	service.activemqService.Subscribe(ctx, "jobOffer.queue", DecodeBody)
}

func DecodeBody(err error, body string) {
	if err != nil {
		return
	}

}

func (service *AuthenticationService) LoginWithCode(ctx context.Context, credentials *domain.PasswordlessCredentials) (*domain.Token, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "LoginWithCode")
	defer span.Finish()

	dbUser, userError := service.GetByEmail(ctx, credentials.Email)
	if userError != nil {
		fmt.Println("no such user")
		return nil, userError
	}

	dbCredentials, credError := service.passwordlessStore.GetByEmail(ctx, credentials.Email)
	if credError != nil {
		fmt.Println("no such user passwordless")
		return nil, credError
	}

	if now := time.Now(); dbCredentials.ExpiringDate.Before(now) {
		err := errors.New("expired code")
		return nil, err
	}

	isCodeCorrect := service.jwtManager.CheckPasswordHash(ctx, (*credentials).Code, (*dbCredentials).Code)
	if !isCodeCorrect {
		fmt.Println("bad code")
		err := errors.New("bad code")
		return nil, err
	}

	validToken, err := service.jwtManager.GenerateJWT(ctx, (*dbUser).Username, (*dbUser).Role)
	if err != nil {
		fmt.Println("failed to generate token")
		err := errors.New("failed to generate token")
		return nil, err
	}

	var token domain.Token
	token.Username = (*dbUser).Username
	token.Role = (*dbUser).Role
	token.TokenString = validToken

	return &token, nil
}

func (service *AuthenticationService) RegisterToGoogleAuthenticatior(ctx context.Context, username string) ([]byte, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "RegisterToGoogleAuthenticatior")
	defer span.Finish()

	user, _ := service.store.GetByUsername(ctx, username)
	runtime.GOMAXPROCS(runtime.NumCPU())
	randomStr := randStr(6, "alphanum")
	fmt.Println(randomStr)
	secret := base32.StdEncoding.EncodeToString([]byte(randomStr))
	authLink := "otpauth://totp/Dislinkt?secret=" + secret + "&issuer=" + user.Email
	code, err := qr.Encode(authLink, qr.L, qr.Auto)
	code, _ = barcode.Scale(code, 512, 512)
	if err != nil {
		err := errors.New("error while creating barcode")
		return nil, err
	}
	buf := &bytes.Buffer{}
	err = png.Encode(buf, code)
	if err != nil {
		err := errors.New("error converting code to bytes")
		return nil, err
	}
	user.MFASecret = secret
	service.store.UpdateMFASecret(ctx, user)
	return buf.Bytes(), nil
}

func (service *AuthenticationService) CheckMFACode(ctx context.Context, username, token string) error {
	span := tracer.StartSpanFromContextMetadata(ctx, "CheckMFACode")
	defer span.Finish()

	user, _ := service.store.GetByUsername(ctx, username)
	fmt.Println(user)
	otpConfig := &dgoogauth.OTPConfig{
		Secret:      strings.TrimSpace(user.MFASecret),
		WindowSize:  3,
		HotpCounter: 0,
	}

	trimmedToken := strings.TrimSpace(token)
	fmt.Println("Trimmed token :", trimmedToken)
	ok, err := otpConfig.Authenticate(trimmedToken)
	if err != nil {
		fmt.Println("erorrrrr1")
		fmt.Println(err)
		return err
	}
	fmt.Printf("Token string [%s] validation is : %v \n", trimmedToken, ok)
	if !ok {
		fmt.Println("erorrrrr2")
		err := errors.New("wrong input")
		return err
	}
	return nil
}

func (service *AuthenticationService) CheckMFACodeUnauthorized(ctx context.Context, username, token string) (*domain.Token, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "CheckMFACodeUnauthorized")
	defer span.Finish()

	user, _ := service.store.GetByUsername(ctx, username)
	fmt.Println(user)
	otpConfig := &dgoogauth.OTPConfig{
		Secret:      strings.TrimSpace(user.MFASecret),
		WindowSize:  3,
		HotpCounter: 0,
	}

	trimmedToken := strings.TrimSpace(token)
	fmt.Println("Trimmed token :", trimmedToken)
	ok, err := otpConfig.Authenticate(trimmedToken)
	if err != nil {
		fmt.Println("erorrrrr1")
		fmt.Println(err)
		return nil, err
	}
	fmt.Printf("Token string [%s] validation is : %v \n", trimmedToken, ok)
	if !ok {
		fmt.Println("erorrrrr2")
		err := errors.New("wrong input")
		return nil, err
	}
	validToken, err := service.jwtManager.GenerateJWT(ctx, (*user).Username, (*user).Role)
	if err != nil {
		fmt.Println("Jwt erorrr")
		err := errors.New("failed to generate token")
		return nil, err
	}

	var tokenRet domain.Token

	tokenRet.Username = (*user).Username
	tokenRet.Role = (*user).Role
	tokenRet.TokenString = validToken
	return &tokenRet, nil
}

func (service *AuthenticationService) ResetSetMFACode(ctx context.Context, username string) {
	span := tracer.StartSpanFromContextMetadata(ctx, "ResetSetMFACode")
	defer span.Finish()

	user, _ := service.store.GetByUsername(ctx, username)
	user.MFASecret = ""
	service.store.UpdateMFASecret(ctx, user)
}

func (service *AuthenticationService) CheckIfMFAActive(ctx context.Context, username string) bool {
	span := tracer.StartSpanFromContextMetadata(ctx, "CheckIfMFAActive")
	defer span.Finish()

	user, _ := service.store.GetByUsername(ctx, username)
	if user.MFASecret == "" {
		return false
	}
	return true
}

func randStr(strSize int, randType string) string {

	var dictionary string

	if randType == "alphanum" {
		dictionary = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	if randType == "alpha" {
		dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	if randType == "number" {
		dictionary = "0123456789"
	}

	var bytes = make([]byte, strSize)
	rand.Read(bytes)
	for k, v := range bytes {
		bytes[k] = dictionary[v%byte(len(dictionary))]
	}
	return string(bytes)
}
