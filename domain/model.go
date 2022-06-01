package domain

import (
	"time"
)

type User struct {
	ID       int    `gorm:"primaryKey"`
	Username string `gorm:"unique" validate:"required,username"`
	Password string
	IsActive bool
	Role     string
	Email    string `gorm:"unique" validate:"required,email"`
}

type ForgotPasswordToken struct {
	ID           int       `gorm:"primaryKey"`
	Token        string    `gorm:"unique"`
	Email        string    `validate:"email"`
	ExpiringDate time.Time `gorm:"date"`
}

type PasswordlessCredentials struct {
	ID           int    `gorm:"primaryKey"`
	Email        string `gorm:"unique" validate:"email"`
	Code         string
	ExpiringDate time.Time `gorm:"date"`
}

type VerificationData struct {
	ID        int    `gorm:"primaryKey"`
	Code      string `gorm:"primaryKey"`
	CodeUsed  bool
	Email     string
	ExpiresAt time.Time `gorm:"date"`
}
