package application

import "github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"

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
	newUser, _ := service.store.Create(user)
	return newUser, nil
}

func (service *AuthenticationService) IsAuthorized(token *domain.Token) {
	//service.store.Create()
}
