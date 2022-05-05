package domain

type User struct {
	ID int `gorm:"primaryKey"`
	//UserId   string `gorm:"unique"`
	Username string `gorm:"unique"`
	Password string
	Role     string
}
