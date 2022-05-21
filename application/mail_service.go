package application

import (
	"fmt"
	"net/smtp"
	"os"
)

type MailService struct {
}

func NewMailServiceService() *MailService {
	return &MailService{}
}

func (service *MailService) SendForgotPasswordMail(token, email string) {

	from := os.Getenv("MAIL_USERNAME ")
	password := os.Getenv("MAIL_PASSWORD")

	to := []string{
		email,
	}

	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	message := []byte("To recover email click here: http://localhost:8083/" + token)

	auth := smtp.PlainAuth("", from, password, smtpHost)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Email Sent Successfully!")
}
