package domain

import "context"

type UserStore interface {
	Create(ctx context.Context, user *User) (*User, error)
	GetAllActiveAccounts(ctx context.Context) (*[]User, error)
	GetActiveByID(ctx context.Context, id int) (*User, error)
	DeleteAll(ctx context.Context)
	GetActiveByUsername(ctx context.Context, username string) (*User, error)
	GetByUsername(ctx context.Context, username string) (*User, error)
	GetActiveByEmail(ctx context.Context, email string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	UpdatePassword(ctx context.Context, user *User) error
	UpdateIsActive(ctx context.Context, user *User) error
	UpdateMFASecret(ctx context.Context, user *User) error
}
