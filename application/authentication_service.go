package application

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"github.com/google/uuid"
	"time"
)

type AuthenticationService struct {
	store             domain.UserStore
	jwtManager        JwtManager
	tokenStore        domain.ForgotPasswordTokenStore
	passwordlessStore domain.PasswordlessStore
	verificationStore domain.VerificationStore
	mailService       *MailService
}

func NewAuthenticationService(store domain.UserStore, tokenStore domain.ForgotPasswordTokenStore, passwordlessStore domain.PasswordlessStore, verificationStore domain.VerificationStore, mailService *MailService) *AuthenticationService {
	return &AuthenticationService{
		store:             store,
		jwtManager:        *NewJwtManager(),
		tokenStore:        tokenStore,
		passwordlessStore: passwordlessStore,
		verificationStore: verificationStore,
		mailService:       mailService,
	}
}

func (service *AuthenticationService) Login(credentials *domain.Credentials) (*domain.Token, error) {
	dbUser, _ := service.store.GetActiveByUsername((*credentials).Username)
	if (*dbUser).Username == "" {
		err := errors.New("bad credentials")
		return nil, err
	}

	isPasswordCorrect := service.jwtManager.CheckPasswordHash((*credentials).Password, (*dbUser).Password)
	if !isPasswordCorrect {
		err := errors.New("bad credentials")
		return nil, err
	}

	validToken, err := service.jwtManager.GenerateJWT((*dbUser).Username, (*dbUser).Role)
	if err != nil {
		err := errors.New("failed to generate token")
		return nil, err
	}

	var token domain.Token
	token.Username = (*dbUser).Username
	token.Role = (*dbUser).Role
	token.TokenString = validToken

	return &token, nil
}

func (service *AuthenticationService) Register(user *domain.User) (*domain.User, error) {
	dbUser, _ := service.store.GetByUsername((*user).Username)
	if (*dbUser).Username != "" {
		err := errors.New("username already exists")
		return nil, err
	}

	dbUser, _ = service.store.GetByEmail((*user).Email)
	if (*dbUser).Username != "" {
		err := errors.New("email already exists")
		return nil, err
	}

	var err error
	(*user).Password, err = service.jwtManager.GenerateHashPassword((*user).Password)
	if err != nil {
		err := errors.New("error in hashing password")
		return nil, err
	}

	(*user).IsActive = false
	newUser, err := service.store.Create(user)

	if err != nil {
		err := errors.New("error in saving user data")
		return nil, err
	}

	verificationData, err := service.verificationStore.Create(&domain.VerificationData{
		Code:      uuid.New().String(),
		Email:     (*newUser).Email,
		ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(1)),
		CodeUsed:  false,
	})
	if err != nil {
		err := errors.New("error in saving verification data")
		return nil, err
	}

	err = service.mailService.SendVerificationEmail((*verificationData).Email, (*verificationData).Code)
	if err != nil {
		err := errors.New("error sending e-mail")
		return nil, err
	}

	return newUser, nil
}

func (service *AuthenticationService) ActivateAccount(code string) (*domain.ActivatedAccount, error) {

	verificationData, err := service.verificationStore.GetByCode(code)
	if err != nil {
		err := errors.New("error reading verification data")
		return nil, err
	}

	user, err := service.store.GetByEmail(verificationData.Email)
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

	err = service.store.UpdateIsActive(user)
	if err != nil {
		err := errors.New("error activating account")
		return nil, err
	}

	err = service.verificationStore.UpdateUsedData(verificationData)
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

func (service *AuthenticationService) SaveToken(email string) (*domain.ForgotPasswordToken, error) {
	var request = domain.ForgotPasswordToken{
		Email:        email,
		Token:        uuid.New().String(),
		ExpiringDate: time.Now().Local().Add(time.Hour * time.Duration(4)),
	}
	fmt.Printf("Token created,%s\n", request.Token)
	return service.tokenStore.Create(&request)
}

func (service *AuthenticationService) GetByEmail(email string) (*domain.User, error) {
	user, err := service.store.GetActiveByEmail(email)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (service *AuthenticationService) CreatePasswordlessCredentials(credentials *domain.PasswordlessCredentials) (*domain.PasswordlessCredentials, error) {
	newCredentials, err := service.passwordlessStore.Create(credentials)
	return newCredentials, err
}

func (service *AuthenticationService) GenerateSecureCode(length int) (string, error) {
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
