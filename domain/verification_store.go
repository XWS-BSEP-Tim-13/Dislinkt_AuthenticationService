package domain

import "context"

type VerificationStore interface {
	Create(ctx context.Context, data *VerificationData) (*VerificationData, error)
	GetById(ctx context.Context, id int) (*VerificationData, error)
	GetByCode(ctx context.Context, code string) (*VerificationData, error)
	UpdateUsedData(ctx context.Context, data *VerificationData) error
}
