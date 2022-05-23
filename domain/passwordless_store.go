package domain

type PasswordlessStore interface {
	Create(passwordless *PasswordlessCredentials) (*PasswordlessCredentials, error)
	GetById(id int) (*PasswordlessCredentials, error)
	GetByEmail(email string) (*PasswordlessCredentials, error)
}
