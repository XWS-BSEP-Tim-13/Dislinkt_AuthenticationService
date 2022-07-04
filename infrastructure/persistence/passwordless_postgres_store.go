package persistence

import (
	"context"
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/tracer"
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

func (store PasswordlessPostgresStore) GetById(ctx context.Context, id int) (*domain.PasswordlessCredentials, error) {
	span := tracer.StartSpanFromContext(ctx, "DB GetById")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	var passwordless domain.PasswordlessCredentials
	result := store.db.Find(&passwordless, id)

	if result.RowsAffected > 0 {
		return &passwordless, nil
	}

	return &domain.PasswordlessCredentials{}, fmt.Errorf("User with id=%s not found", id)
}

func (store PasswordlessPostgresStore) GetByEmail(ctx context.Context, email string) (*domain.PasswordlessCredentials, error) {
	span := tracer.StartSpanFromContext(ctx, "DB GetByEmail")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	var user domain.PasswordlessCredentials
	result := store.db.Where("email = ?", email).Find(&user)

	if result.RowsAffected > 0 {
		return &user, nil
	}

	return &domain.PasswordlessCredentials{}, fmt.Errorf("User with email=%s not found", email)
}

func (store PasswordlessPostgresStore) Create(ctx context.Context, passwordless *domain.PasswordlessCredentials) (*domain.PasswordlessCredentials, error) {
	span := tracer.StartSpanFromContext(ctx, "DB Create")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	result := store.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "email"}},
		DoUpdates: clause.AssignmentColumns([]string{"code", "expiring_date"}),
	}).Create(&passwordless)

	if result.Error != nil {
		return nil, result.Error
	}
	var newCredentials *domain.PasswordlessCredentials
	newCredentials, _ = store.GetById(ctx, passwordless.ID)
	return newCredentials, nil
}
