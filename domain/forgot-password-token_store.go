package domain

import "context"

type ForgotPasswordTokenStore interface {
	Create(ctx context.Context, user *ForgotPasswordToken) (*ForgotPasswordToken, error)
	GetById(ctx context.Context, id int) (*ForgotPasswordToken, error)
	GetByToken(ctx context.Context, token string) (*ForgotPasswordToken, error)
	DeleteAll(ctx context.Context)
	Delete(ctx context.Context, id int)
}
