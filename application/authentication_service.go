package application

import (
	"errors"
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"github.com/google/uuid"
	"time"
)

type AuthenticationService struct {
	store      domain.UserStore
	jwtManager JwtManager
	tokenStore domain.ForgotPasswordTokenStore
}

func NewAuthenticationService(store domain.UserStore, tokenStore domain.ForgotPasswordTokenStore) *AuthenticationService {
	return &AuthenticationService{
		store:      store,
		jwtManager: *NewJwtManager(),
		tokenStore: tokenStore,
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

func (service *AuthenticationService) CheckIfTokenExists(token string) (*domain.ForgotPasswordToken, error) {
	return service.tokenStore.GetByToken(token)
}

func (service *AuthenticationService) IsAuthorized(token *domain.Token) {
	//service.store.Create()
}
