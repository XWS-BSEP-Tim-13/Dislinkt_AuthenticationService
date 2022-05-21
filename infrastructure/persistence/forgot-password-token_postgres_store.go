package persistence

import (
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"gorm.io/gorm"
)

type ForgotPasswordTokenPostgresStore struct {
	db *gorm.DB
}

func NewForgotPasswordTokenPostgresStore(db *gorm.DB) (domain.ForgotPasswordTokenStore, error) {
	err := db.AutoMigrate(&domain.ForgotPasswordToken{})
	if err != nil {
		return nil, err
	}
	return &ForgotPasswordTokenPostgresStore{
		db: db,
	}, nil
}

func (store ForgotPasswordTokenPostgresStore) Create(token *domain.ForgotPasswordToken) (*domain.ForgotPasswordToken, error) {
	result := store.db.Create(token)
	if result.Error != nil {
		return nil, result.Error
	}
	var newToken *domain.ForgotPasswordToken
	newToken, _ = store.GetById(newToken.ID)
	return newToken, nil
}

func (store ForgotPasswordTokenPostgresStore) GetById(id int) (*domain.ForgotPasswordToken, error) {
	var token domain.ForgotPasswordToken
	result := store.db.Find(&token, id)

	if result.RowsAffected > 0 {
		return &token, nil
	}

	return &domain.ForgotPasswordToken{}, fmt.Errorf("User with id=%s not found", id)
}

func (store ForgotPasswordTokenPostgresStore) GetByToken(tokenS string) (*domain.ForgotPasswordToken, error) {
	var token domain.ForgotPasswordToken
	result := store.db.Where("token = ?", tokenS).Find(&token)

	if result.RowsAffected > 0 {
		return &token, nil
	}

	return &domain.ForgotPasswordToken{}, fmt.Errorf("Token with token=%s not found", tokenS)
}
