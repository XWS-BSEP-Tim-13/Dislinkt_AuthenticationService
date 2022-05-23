package domain

import (
	"time"
)

type User struct {
	ID       int    `gorm:"primaryKey"`
	Username string `gorm:"unique"`
	Password string
	IsActive bool
	Role     string
	Email    string `gorm:"unique"`
}

type ForgotPasswordToken struct {
	ID           int    `gorm:"primaryKey"`
	Token        string `gorm:"unique"`
	Email        string
	ExpiringDate time.Time `gorm:"date"`
}

type PasswordlessCredentials struct {
	ID           int    `gorm:"primaryKey"`
	Email        string `gorm:"unique"`
	Code         string
	ExpiringDate time.Time `gorm:"date"`
}

type VerificationData struct {
	ID        int    `gorm:"primaryKey"`
	Code      string `gorm:"primaryKey"`
	Email     string
	ExpiresAt time.Time `gorm:"date"`
}
