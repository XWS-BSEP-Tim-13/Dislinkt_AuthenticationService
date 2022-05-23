package application

import (
	"crypto/rand"
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

func (service *MailService) SendPasswordlessCode(email string) {

	from := os.Getenv("MAIL_USERNAME")
	password := os.Getenv("MAIL_PASSWORD")

	to := []string{
		email,
	}
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	secureCode, _ := GenerateOTP(6)

	body := "Your code is: " + secureCode
	message := []byte("From: " + from + "\r\n" +
		email + "\r\n" +
		"Subject: Six digit code for passwordless login\r\n\r\n" +
		body + "\r\n")
	auth := smtp.PlainAuth("", from, password, smtpHost)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	if err != nil {
		fmt.Println(err)
		return
	}
}

const otpChars = "1234567890"

func GenerateOTP(length int) (string, error) {
	buffer := make([]byte, length)
	_, err := rand.Read(buffer)
	if err != nil {
		return "", err
	}

	otpCharsLength := len(otpChars)
	for i := 0; i < length; i++ {
		buffer[i] = otpChars[int(buffer[i])%otpCharsLength]
	}

	return string(buffer), nil
}
