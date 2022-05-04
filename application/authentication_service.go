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

func (service *AuthenticationService) GetAll() (*[]domain.User, error) {
	return service.store.GetAll()
}

func (service *AuthenticationService) DeleteAll() {
	service.store.DeleteAll()
}
