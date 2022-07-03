package persistence

import (
	"context"
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/tracer"
	"gorm.io/gorm"
)

type ForgotPasswordTokenPostgresStore struct {
	db *gorm.DB
}

func (store ForgotPasswordTokenPostgresStore) Delete(ctx context.Context, id int) {
	span := tracer.StartSpanFromContextMetadata(ctx, "DB Delete")
	defer span.Finish()

	err := store.db.Delete(&domain.ForgotPasswordToken{}, id)
	if err != nil {
		fmt.Printf("Error while deleting token\n")
	}
}

func (store ForgotPasswordTokenPostgresStore) DeleteAll(ctx context.Context) {
	span := tracer.StartSpanFromContextMetadata(ctx, "DB DeleteAll")
	defer span.Finish()

	store.db.Session(&gorm.Session{AllowGlobalUpdate: true}).
		Delete(&domain.ForgotPasswordToken{})
}

func NewForgotPasswordTokenPostgresStore(db *gorm.DB) (domain.ForgotPasswordTokenStore, error) {
	db.Migrator().DropTable(&domain.ForgotPasswordToken{})
	err := db.AutoMigrate(&domain.ForgotPasswordToken{})
	if err != nil {
		return nil, err
	}
	return &ForgotPasswordTokenPostgresStore{
		db: db,
	}, nil
}

func (store ForgotPasswordTokenPostgresStore) Create(ctx context.Context, token *domain.ForgotPasswordToken) (*domain.ForgotPasswordToken, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "DB Create")
	defer span.Finish()

	result := store.db.Create(token)
	fmt.Printf("Creating token %s\n", token.Token)
	if result.Error != nil {
		fmt.Printf("Error while creating\n")
		return nil, result.Error
	}
	newToken, err := store.GetById(ctx, token.ID)
	if err != nil {
		fmt.Printf("Error with get by id\n")
		return nil, result.Error
	}
	return newToken, nil
}

func (store ForgotPasswordTokenPostgresStore) GetById(ctx context.Context, id int) (*domain.ForgotPasswordToken, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "DB GetById")
	defer span.Finish()

	var token domain.ForgotPasswordToken
	result := store.db.Find(&token, id)

	if result.RowsAffected > 0 {
		return &token, nil
	}

	return &domain.ForgotPasswordToken{}, fmt.Errorf("user with id=%s not found", id)
}

func (store ForgotPasswordTokenPostgresStore) GetByToken(ctx context.Context, tokenS string) (*domain.ForgotPasswordToken, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "DB GetByToken")
	defer span.Finish()

	var token domain.ForgotPasswordToken
	result := store.db.Where("token = ?", tokenS).Find(&token)

	if result.RowsAffected > 0 {
		return &token, nil
	}

	return &domain.ForgotPasswordToken{}, fmt.Errorf("token with token=%s not found", tokenS)
}
