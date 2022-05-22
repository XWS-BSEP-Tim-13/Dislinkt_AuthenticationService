package persistence

import (
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"gorm.io/gorm"
)

type PasswordlessPostgresStore struct {
	db *gorm.DB
}

func (store PasswordlessPostgresStore) GetById(id int) (*domain.PasswordlesCredentials, error) {
	var passwordless domain.PasswordlesCredentials
	result := store.db.Find(&passwordless, id)

	if result.RowsAffected > 0 {
		return &passwordless, nil
	}

	return &domain.PasswordlesCredentials{}, fmt.Errorf("User with id=%s not found", id)
}

func (store PasswordlessPostgresStore) Create(passwordless *domain.PasswordlesCredentials) (*domain.PasswordlesCredentials, error) {
	result := store.db.Create(passwordless)
	if result.Error != nil {
		return nil, result.Error
	}
	var newCredentials *domain.PasswordlesCredentials
	newCredentials, _ = store.GetById(newCredentials.ID)
	return newCredentials, nil
}

func NewPasswordlessPostgresStore(db *gorm.DB) (domain.PasswordlessStore, error) {
	err := db.AutoMigrate(&domain.PasswordlesCredentials{})
	if err != nil {
		return nil, err
	}
	return &PasswordlessPostgresStore{
		db: db,
	}, nil
}
