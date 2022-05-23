package domain

import "time"

type User struct {
	ID int `gorm:"primaryKey"`
	//UserId   string `gorm:"unique"`
	Username string `gorm:"unique"`
	Password string
	Role     string
	Email    string `gorm:"unique"`
}

type ForgotPasswordToken struct {
	ID           int    `gorm:"primaryKey"`
	Token        string `gorm:"unique"`
	Email        string
	ExpiringDate time.Time `gorm:"date"`
}
