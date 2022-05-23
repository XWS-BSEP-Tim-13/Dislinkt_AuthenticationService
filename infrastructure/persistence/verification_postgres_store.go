package persistence

import (
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"gorm.io/gorm"
)

type VerificationPostgresStore struct {
	db *gorm.DB
}

func NewVerificationPostgresStore(db *gorm.DB) (domain.VerificationStore, error) {
	err := db.AutoMigrate(&domain.VerificationData{})
	if err != nil {
		return nil, err
	}
	return &VerificationPostgresStore{
		db: db,
	}, nil
}

func (store VerificationPostgresStore) Create(data *domain.VerificationData) (*domain.VerificationData, error) {
	result := store.db.Create(data)
	if result.Error != nil {
		return nil, result.Error
	}

	var newData *domain.VerificationData
	newData, _ = store.GetById(newData.ID)
	return newData, nil
}

func (store VerificationPostgresStore) GetById(id int) (*domain.VerificationData, error) {
	var data domain.VerificationData
	result := store.db.Find(&data, id)

	if result.RowsAffected > 0 {
		return &data, nil
	}

	return &domain.VerificationData{}, fmt.Errorf("data with id=%s not found", id)
}

func (store VerificationPostgresStore) GetByCode(code string) (*domain.VerificationData, error) {
	var data domain.VerificationData
	result := store.db.Where("code = ?", code).Find(&data)

	if result.RowsAffected > 0 {
		return &data, nil
	}

	return &domain.VerificationData{}, fmt.Errorf("data with code=%s not found", code)
}
