package persistence

import (
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type PasswordlessPostgresStore struct {
	db *gorm.DB
}

func NewPasswordlessPostgresStore(db *gorm.DB) (domain.PasswordlessStore, error) {
	err := db.AutoMigrate(&domain.PasswordlessCredentials{})
	if err != nil {
		return nil, err
	}
	return &PasswordlessPostgresStore{
		db: db,
	}, nil
}

func (store PasswordlessPostgresStore) GetById(id int) (*domain.PasswordlessCredentials, error) {
	var passwordless domain.PasswordlessCredentials
	result := store.db.Find(&passwordless, id)

	if result.RowsAffected > 0 {
		return &passwordless, nil
	}

	return &domain.PasswordlessCredentials{}, fmt.Errorf("User with id=%s not found", id)
}

func (store PasswordlessPostgresStore) GetByEmail(email string) (*domain.PasswordlessCredentials, error) {
	var user domain.PasswordlessCredentials
	result := store.db.Where("email = ?", email).Find(&user)

	if result.RowsAffected > 0 {
		return &user, nil
	}

	return &domain.PasswordlessCredentials{}, fmt.Errorf("User with email=%s not found", email)
}

func (store PasswordlessPostgresStore) Create(passwordless *domain.PasswordlessCredentials) (*domain.PasswordlessCredentials, error) {
	result := store.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "email"}},
		DoUpdates: clause.AssignmentColumns([]string{"code", "expiring_date"}),
	}).Create(&passwordless)

	if result.Error != nil {
		return nil, result.Error
	}
	var newCredentials *domain.PasswordlessCredentials
	newCredentials, _ = store.GetById(passwordless.ID)
	return newCredentials, nil
}
