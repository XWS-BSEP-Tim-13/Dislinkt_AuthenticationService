package persistence

import (
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"gorm.io/gorm"
)

type ForgotPasswordTokenPostgresStore struct {
	db *gorm.DB
}

func (store ForgotPasswordTokenPostgresStore) Delete(id int) {
	err := store.db.Delete(&domain.ForgotPasswordToken{}, id)
	if err != nil {
		fmt.Printf("Error while deleting token")
	}
}

func (store ForgotPasswordTokenPostgresStore) DeleteAll() {
	store.db.Session(&gorm.Session{AllowGlobalUpdate: true}).
		Delete(&domain.ForgotPasswordToken{})
}

func NewForgotPasswordTokenPostgresStore(db *gorm.DB) (domain.ForgotPasswordTokenStore, error) {
	//db.Migrator().DropTable(&domain.ForgotPasswordToken{})
	err := db.AutoMigrate(&domain.ForgotPasswordToken{})
	if err != nil {
		fmt.Printf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa\n")
		return nil, err
	}
	return &ForgotPasswordTokenPostgresStore{
		db: db,
	}, nil
}

func (store ForgotPasswordTokenPostgresStore) Create(token *domain.ForgotPasswordToken) (*domain.ForgotPasswordToken, error) {
	result := store.db.Create(token)
	fmt.Printf("Creating token %s\n", token.Token)
	if result.Error != nil {
		fmt.Printf("Error while creating")
		return nil, result.Error
	}
	newToken, err := store.GetById(token.ID)
	if err != nil {
		fmt.Printf("Error while creating")
		return nil, result.Error
	}
	return newToken, nil
}

func (store ForgotPasswordTokenPostgresStore) GetById(id int) (*domain.ForgotPasswordToken, error) {
	var token domain.ForgotPasswordToken
	result := store.db.Find(&token, id)

	if result.RowsAffected > 0 {
		return &token, nil
	}

	return &domain.ForgotPasswordToken{}, fmt.Errorf("user with id=%s not found", id)
}

func (store ForgotPasswordTokenPostgresStore) GetByToken(tokenS string) (*domain.ForgotPasswordToken, error) {
	var token domain.ForgotPasswordToken
	result := store.db.Where("token = ?", tokenS).Find(&token)

	if result.RowsAffected > 0 {
		return &token, nil
	}

	return &domain.ForgotPasswordToken{}, fmt.Errorf("token with token=%s not found", tokenS)
}
