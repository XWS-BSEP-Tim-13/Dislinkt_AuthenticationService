package domain

type UserStore interface {
	Create(user *User) (*User, error)
	GetAllActiveAccounts() (*[]User, error)
	GetActiveByID(id int) (*User, error)
	DeleteAll()
	GetActiveByUsername(username string) (*User, error)
	GetByUsername(username string) (*User, error)
	GetActiveByEmail(email string) (*User, error)
}
