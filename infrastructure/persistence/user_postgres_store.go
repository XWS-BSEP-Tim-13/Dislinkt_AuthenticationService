package persistence

import (
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"gorm.io/gorm"
)

type AuthenticationPostgresStore struct {
	db *gorm.DB
}

func NewAuthenticationPostgresStore(db *gorm.DB) (domain.UserStore, error) {
	err := db.AutoMigrate(&domain.User{})
	if err != nil {
		return nil, err
	}
	return &AuthenticationPostgresStore{
		db: db,
	}, nil
}

func (store *AuthenticationPostgresStore) Create(user *domain.User) (*domain.User, error) {
	result := store.db.Create(user)
	if result.Error != nil {
		return nil, result.Error
	}
	var newUser *domain.User
	newUser, _ = store.GetById(user.UserId)
	return newUser, nil
}

func (store *AuthenticationPostgresStore) GetById(id string) (*domain.User, error) {
	var user domain.User
	result := store.db.Find(&user, id)

	if result.RowsAffected > 0 {
		return &user, nil
	}

	return &domain.User{}, fmt.Errorf("User with id=%s not found", id)
}

func (store *AuthenticationPostgresStore) GetByUsername(username string) (*domain.User, error) {
	var user domain.User
	result := store.db.Where("username = ?", username).Find(&user)

	if result.RowsAffected > 0 {
		return &user, nil
	}

	return &domain.User{}, fmt.Errorf("User with username=%s not found", username)
}

func (store *AuthenticationPostgresStore) GetAll() (*[]domain.User, error) {
	var users []domain.User
	result := store.db.Find(&users)
	if result.Error != nil {
		return nil, result.Error
	}
	return &users, nil
}

func (store *AuthenticationPostgresStore) DeleteAll() {
	store.db.Session(&gorm.Session{AllowGlobalUpdate: true}).
		Delete(&domain.User{})
}
