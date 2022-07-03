package domain

import "context"

type PasswordlessStore interface {
	Create(ctx context.Context, passwordless *PasswordlessCredentials) (*PasswordlessCredentials, error)
	GetById(ctx context.Context, id int) (*PasswordlessCredentials, error)
	GetByEmail(ctx context.Context, email string) (*PasswordlessCredentials, error)
}
