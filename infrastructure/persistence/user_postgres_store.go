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
	fmt.Printf("Creating user %d\n", user.ID)
	if result.Error != nil {
		return nil, result.Error
	}
	var newUser *domain.User
	newUser, _ = store.GetActiveByID(user.ID)
	return newUser, nil
}

func (store *AuthenticationPostgresStore) GetActiveByID(id int) (*domain.User, error) {
	var user domain.User
	result := store.db.Where("is_active = true").Find(&user, id)

	if result.RowsAffected > 0 {
		return &user, nil
	}

	return &domain.User{}, fmt.Errorf("User with id=%s not found", id)
}

func (store *AuthenticationPostgresStore) GetActiveByUsername(username string) (*domain.User, error) {
	var user domain.User
	result := store.db.Where("username = ?", username).Where("is_active = true").Find(&user)

	if result.RowsAffected > 0 {
		return &user, nil
	}

	return &domain.User{}, fmt.Errorf("User with username=%s not found", username)
}

func (store *AuthenticationPostgresStore) GetByUsername(username string) (*domain.User, error) {
	var user domain.User
	result := store.db.Where("username = ?", username).Find(&user)

	if result.RowsAffected > 0 {
		return &user, nil
	}

	return &domain.User{}, fmt.Errorf("User with username=%s not found", username)
}

func (store *AuthenticationPostgresStore) GetAllActiveAccounts() (*[]domain.User, error) {
	var users []domain.User
	result := store.db.Where("is_active = true").Find(&users)
	if result.Error != nil {
		return nil, result.Error
	}
	return &users, nil
}

func (store *AuthenticationPostgresStore) DeleteAll() {
	store.db.Session(&gorm.Session{AllowGlobalUpdate: true}).
		Delete(&domain.User{})
}

func (store *AuthenticationPostgresStore) GetActiveByEmail(email string) (*domain.User, error) {
	var user domain.User
	result := store.db.Where("email = ?", email).Where("is_active = true").Find(&user)

	if result.RowsAffected > 0 {
		return &user, nil
	}

	return &domain.User{}, fmt.Errorf("User with email=%s not found", email)
}

func (store *AuthenticationPostgresStore) GetByEmail(email string) (*domain.User, error) {
	var user domain.User
	result := store.db.Where("email = ?", email).Find(&user)

	if result.RowsAffected > 0 {
		return &user, nil
	}

	return &domain.User{}, fmt.Errorf("User with email=%s not found", email)
}
