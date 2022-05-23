package domain

type UserStore interface {
	Create(user *User) (*User, error)
	GetAll() (*[]User, error)
	GetById(id int) (*User, error)
	DeleteAll()
	GetByUsername(username string) (*User, error)
	GetByEmail(email string) (*User, error)
	UpdatePassword(user *User) error
}
