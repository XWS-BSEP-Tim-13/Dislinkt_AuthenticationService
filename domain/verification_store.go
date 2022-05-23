package domain

type VerificationStore interface {
	Create(data *VerificationData) (*VerificationData, error)
	GetById(id int) (*VerificationData, error)
}
