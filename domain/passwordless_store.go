package domain

type PasswordlessStore interface {
	Create(passwordless *PasswordlesCredentials) (*PasswordlesCredentials, error)
	GetById(id int) (*PasswordlesCredentials, error)
}
