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
}

func NewAuthenticationService(store domain.UserStore, tokenStore domain.ForgotPasswordTokenStore, passwordlessStore domain.PasswordlessStore) *AuthenticationService {
	return &AuthenticationService{
		store:             store,
		jwtManager:        *NewJwtManager(),
		tokenStore:        tokenStore,
		passwordlessStore: passwordlessStore,
	}
}

func (service *AuthenticationService) Login(credentials *domain.Credentials) (*domain.Token, error) {
	dbUser, _ := service.store.GetByUsername((*credentials).Username)
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

	var err error
	(*user).Password, err = service.jwtManager.GenerateHashPassword((*user).Password)
	if err != nil {
		err := errors.New("error in hashing password")
		return nil, err
	}

	newUser, err := service.store.Create(user)
	return newUser, err
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

func (service *AuthenticationService) IsAuthorized(token *domain.Token) {
	//service.store.Create()
}

func (service *AuthenticationService) GetByEmail(email string) (*domain.User, error) {
	user, err := service.store.GetByEmail(email)
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

func (service *AuthenticationService) HashSecureCode(code string) (string, error) {
	hashed, err := service.jwtManager.GenerateHashPassword(code)
	return hashed, err
}

func (service *AuthenticationService) LoginWithCode(credentials *domain.PasswordlessCredentials) (*domain.Token, error) {
	dbUser, userError := service.GetByEmail(credentials.Email)
	if userError != nil {
		return nil, userError
	}

	dbCredentials, credError := service.passwordlessStore.GetByEmail(credentials.Email)
	if credError != nil {
		return nil, credError
	}

	isCodeCorrect := service.jwtManager.CheckPasswordHash((*credentials).Code, (*dbCredentials).Code)
	if !isCodeCorrect {
		err := errors.New("bad code")
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
