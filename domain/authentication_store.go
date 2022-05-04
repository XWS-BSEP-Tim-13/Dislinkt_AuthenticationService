package domain

type UserStore interface {
	Create(user *User) (*User, error)
	GetAll() (*[]User, error)
	GetById(id string) (*User, error)
	DeleteAll()
	GetByUsername(username string) (*User, error)
}
