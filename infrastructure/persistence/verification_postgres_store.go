package persistence

import (
	"context"
	"errors"
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/tracer"
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

func (store *VerificationPostgresStore) Create(ctx context.Context, data *domain.VerificationData) (*domain.VerificationData, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "DB Create")
	defer span.Finish()

	result := store.db.Create(data)
	if result.Error != nil {
		return nil, result.Error
	}

	var newData *domain.VerificationData
	newData, _ = store.GetById(ctx, data.ID)
	return newData, nil
}

func (store *VerificationPostgresStore) GetById(ctx context.Context, id int) (*domain.VerificationData, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "DB GetById")
	defer span.Finish()

	var data domain.VerificationData
	result := store.db.Find(&data, id)

	if result.RowsAffected > 0 {
		return &data, nil
	}

	return &domain.VerificationData{}, fmt.Errorf("data with id=%s not found", id)
}

func (store *VerificationPostgresStore) GetByCode(ctx context.Context, code string) (*domain.VerificationData, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "DB GetByCode")
	defer span.Finish()

	var data domain.VerificationData
	result := store.db.Where("code = ?", code).Find(&data)

	if result.RowsAffected > 0 {
		return &data, nil
	}

	return &domain.VerificationData{}, fmt.Errorf("data with code=%s not found", code)
}

func (store *VerificationPostgresStore) UpdateUsedData(ctx context.Context, verificationData *domain.VerificationData) error {
	span := tracer.StartSpanFromContextMetadata(ctx, "DB UpdateUsedData")
	defer span.Finish()

	tx := store.db.Model(&domain.VerificationData{}).
		Where("id = ?", verificationData.ID).
		Update("code_used", true)

	if tx.Error != nil {
		return tx.Error
	}

	if tx.RowsAffected != 1 {
		return errors.New("update error")
	}

	return nil
}
