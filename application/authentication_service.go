package application

import (
	"errors"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"golang.org/x/crypto/bcrypt"
)

type AuthenticationService struct {
	store domain.UserStore
}

func NewAuthenticationService(store domain.UserStore) *AuthenticationService {
	return &AuthenticationService{
		store: store,
	}
}

func (service *AuthenticationService) Login(credentials *[]domain.Credentials) (*domain.User, error) {
	return nil, nil
}

func (service *AuthenticationService) Register(user *domain.User) (*domain.User, error) {
	dbUser, _ := service.store.GetByUsername((*user).Username)

	if dbUser.Username != "" {
		err := errors.New("username already exists")
		return nil, err
	}

	var err error
	(*user).Password, err = generateHashPassword((*user).Password)
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

func generateHashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}
