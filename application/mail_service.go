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

	from := os.Getenv("MAIL_USERNAME")
	password := os.Getenv("MAIL_PASSWORD")

	to := []string{
		email,
	}
	fmt.Printf("Token mail %s\n", token)
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	body := "To recover email click here: http://localhost:8083/" + token
	message := []byte("From: " + os.Getenv("MAIL_USERNAME") + "\r\n" +
		email + "\r\n" +
		"Subject: Recover password\r\n\r\n" +
		body + "\r\n")
	//message := []byte("This is a test email message.")
	auth := smtp.PlainAuth("", from, password, smtpHost)
	fmt.Printf("Sending email last, %s,drugi%s,treci%s\n", os.Getenv("MAIL_PASSWORD"), os.Getenv("MAIL_USERNAME"), os.Getenv("MAIL_USERNAME "))
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Email Sent Successfully!")
}
