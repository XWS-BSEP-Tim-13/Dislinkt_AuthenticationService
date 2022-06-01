package config

import "os"

type EmailConfig struct {
	EmailUsername string
	EmailPassword string
}

func NewEmailConfig() *EmailConfig {
	return &EmailConfig{
		EmailUsername: os.Getenv("MAIL_USERNAME"),
		EmailPassword: os.Getenv("MAIL_PASSWORD"),
	}
}
