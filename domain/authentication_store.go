package domain

type UserStore interface {
	Create(user *User) error
	GetAll() (*[]User, error)
	GetById(id string) (*User, error)
	DeleteAll()
}
