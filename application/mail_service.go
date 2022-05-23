package application

import (
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/startup/config"
	"net/smtp"
	"os"
)

type MailService struct {
	emailConfig *config.EmailConfig
}

func NewMailServiceService() *MailService {
	return &MailService{}
}

func (service *MailService) SendForgotPasswordMail(token, email string) {

	from := service.emailConfig.EmailUsername
	password := service.emailConfig.EmailPassword

	to := []string{
		email,
	}
	fmt.Printf("Token mail %s\n", token)
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	body := "To recover email click here: http://localhost:8083/" + token
	message := []byte("From: " + from + "\r\n" +
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

func (service *MailService) SendPasswordlessCode(email string, secureCode string) error {

	from := service.emailConfig.EmailUsername
	password := service.emailConfig.EmailPassword

	fmt.Println("From: ", from)

	to := []string{
		email,
	}
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	body := "Your code is: " + secureCode
	message := []byte("From: " + from + "\r\n" +
		"Subject: Six digit code for passwordless login\r\n\r\n" +
		body + "\r\n")
	auth := smtp.PlainAuth("", from, password, smtpHost)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	if err != nil {
		fmt.Println(err)
	}
	return err
}

func (service *MailService) SendVerificationEmail(email string, code string) error {

	to := []string{
		email,
	}

	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	body := "<h1 style=\"font-size:2rem;\">Activate your account!</h1>" +
		"<p style=\"text-align:center;\">Please click on button below to activate your account:</p>" +
		"<a style=\"padding:1rem; background-color:#800000; color:white; border: none; border-radius:5px; text-decoration: none; height: 2.5rem;\"" +
		"href=\"https://localhost:8083/activate/" + code + "\">" +
		"" +
		"</a>" +
		"<p style=\"text-align:center;\">DISLINKT</p>"

	message := []byte("From: " + service.emailConfig.EmailUsername + "\r\n" +
		"Subject: DISLINKT Account Activation\r\n\r\n" +
		body + "\r\n")

	auth := smtp.PlainAuth("", service.emailConfig.EmailUsername, service.emailConfig.EmailPassword, smtpHost)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, service.emailConfig.EmailUsername, to, message)
	if err != nil {
		fmt.Println(err)
	}

	return err
}
