package domain

type User struct {
	UserId   string `gorm:"unique"`
	Username string `gorm:"unique"`
	Password string
	Role     string
}
