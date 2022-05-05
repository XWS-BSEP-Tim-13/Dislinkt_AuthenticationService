package application

import (
	"errors"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
)

type AuthenticationService struct {
	store      domain.UserStore
	jwtManager JwtManager
}

func NewAuthenticationService(store domain.UserStore) *AuthenticationService {
	return &AuthenticationService{
		store:      store,
		jwtManager: *NewJwtManager(),
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

func (service *AuthenticationService) IsAuthorized(token *domain.Token) {
	//service.store.Create()
}
