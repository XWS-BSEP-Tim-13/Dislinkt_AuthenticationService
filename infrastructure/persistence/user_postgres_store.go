package persistence

import (
	"context"
	"errors"
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/tracer"
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

func (store *AuthenticationPostgresStore) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "Connect")
	defer span.Finish()

	result := store.db.Create(user)
	fmt.Printf("Creating user %d\n", user.ID)
	if result.Error != nil {
		return nil, result.Error
	}
	var newUser *domain.User
	newUser, _ = store.GetByID(ctx, user.ID)
	return newUser, nil
}

func (store *AuthenticationPostgresStore) GetActiveByID(ctx context.Context, id int) (*domain.User, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "Connect")
	defer span.Finish()

	var user domain.User
	result := store.db.Where("is_active = true").Find(&user, id)

	if result.RowsAffected > 0 {
		return &user, nil
	}

	return &domain.User{}, fmt.Errorf("User with id=%s not found", id)
}

func (store *AuthenticationPostgresStore) GetByID(ctx context.Context, id int) (*domain.User, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "Connect")
	defer span.Finish()

	var user domain.User
	result := store.db.Find(&user, id)

	if result.RowsAffected > 0 {
		return &user, nil
	}

	return &domain.User{}, fmt.Errorf("User with id=%s not found", id)
}

func (store *AuthenticationPostgresStore) GetActiveByUsername(ctx context.Context, username string) (*domain.User, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "Connect")
	defer span.Finish()

	var user domain.User
	result := store.db.Where("username = ?", username).Where("is_active = true").Find(&user)

	if result.RowsAffected > 0 {
		return &user, nil
	}

	return &domain.User{}, fmt.Errorf("User with username=%s not found", username)
}

func (store *AuthenticationPostgresStore) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "Connect")
	defer span.Finish()

	var user domain.User
	result := store.db.Where("username = ?", username).Find(&user)

	if result.RowsAffected > 0 {
		return &user, nil
	}
	return &domain.User{}, fmt.Errorf("User with username=%s not found", username)
}

func (store *AuthenticationPostgresStore) UpdatePassword(ctx context.Context, user *domain.User) error {
	span := tracer.StartSpanFromContextMetadata(ctx, "Connect")
	defer span.Finish()

	if err := store.db.Model(&user).Where("id = ?", user.ID).Update("password", user.Password).Error; err != nil {
		return fmt.Errorf("failed to update password")
	}
	return nil
}

func (store *AuthenticationPostgresStore) UpdateMFASecret(ctx context.Context, user *domain.User) error {
	span := tracer.StartSpanFromContextMetadata(ctx, "Connect")
	defer span.Finish()

	if err := store.db.Model(&user).Where("id = ?", user.ID).Update("mfa_secret", user.MFASecret).Error; err != nil {
		return fmt.Errorf("failed to update password")
	}
	return nil
}

func (store *AuthenticationPostgresStore) GetAllActiveAccounts(ctx context.Context) (*[]domain.User, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "Connect")
	defer span.Finish()

	var users []domain.User
	result := store.db.Where("is_active = true").Find(&users)
	if result.Error != nil {
		return nil, result.Error
	}
	return &users, nil
}

func (store *AuthenticationPostgresStore) DeleteAll(ctx context.Context) {
	span := tracer.StartSpanFromContextMetadata(ctx, "Connect")
	defer span.Finish()

	store.db.Session(&gorm.Session{AllowGlobalUpdate: true}).
		Delete(&domain.User{})
}

func (store *AuthenticationPostgresStore) GetActiveByEmail(ctx context.Context, email string) (*domain.User, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "Connect")
	defer span.Finish()

	var user domain.User
	result := store.db.Where("email = ?", email).Where("is_active = true").Find(&user)

	if result.RowsAffected > 0 {
		return &user, nil
	}

	return &domain.User{}, fmt.Errorf("User with email=%s not found", email)
}

func (store *AuthenticationPostgresStore) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "Connect")
	defer span.Finish()

	var user domain.User
	result := store.db.Where("email = ?", email).Find(&user)

	if result.RowsAffected > 0 {
		return &user, nil
	}

	return &domain.User{}, fmt.Errorf("User with email=%s not found", email)
}

func (store *AuthenticationPostgresStore) UpdateIsActive(ctx context.Context, user *domain.User) error {
	span := tracer.StartSpanFromContextMetadata(ctx, "Connect")
	defer span.Finish()

	tx := store.db.Model(&domain.User{}).
		Where("id = ?", user.ID).
		Update("is_active", true)

	if tx.Error != nil {
		return tx.Error
	}

	if tx.RowsAffected != 1 {
		return errors.New("update error")
	}

	return nil
}
