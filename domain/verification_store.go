package domain

type VerificationStore interface {
	Create(data *VerificationData) (*VerificationData, error)
	GetById(id int) (*VerificationData, error)
	GetByCode(code string) (*VerificationData, error)
	UpdateUsedData(data *VerificationData) error
}
