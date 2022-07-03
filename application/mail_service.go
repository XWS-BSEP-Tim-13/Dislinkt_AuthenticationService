package application

import (
	"context"
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/startup/config"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/tracer"
	"net/smtp"
	"os"
)

type MailService struct {
	emailConfig *config.EmailConfig
}

func NewMailServiceService() *MailService {
	return &MailService{
		emailConfig: config.NewEmailConfig(),
	}
}

func (service *MailService) SendForgotPasswordMail(ctx context.Context, token, email string) {
	span := tracer.StartSpanFromContextMetadata(ctx, "SendForgotPasswordMail")
	defer span.Finish()

	from := service.emailConfig.EmailUsername
	password := service.emailConfig.EmailPassword

	to := []string{
		email,
	}
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	body := "To recover email click here: https://localhost:8083/change-password/" + token
	message := []byte("From: " + from + "\r\n" +
		email + "\r\n" +
		"Subject: Recover password\r\n\r\n" +
		body + "\r\n")
	auth := smtp.PlainAuth("", from, password, smtpHost)
	fmt.Printf("Sending email last, %s,drugi%s,treci%s\n", os.Getenv("MAIL_PASSWORD"), os.Getenv("MAIL_USERNAME"), os.Getenv("MAIL_USERNAME "))
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Email Sent Successfully!")
}

func (service *MailService) SendPasswordlessCode(ctx context.Context, email string, secureCode string) error {
	span := tracer.StartSpanFromContextMetadata(ctx, "SendPasswordlessCode")
	defer span.Finish()

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

func (service *MailService) SendVerificationEmail(ctx context.Context, email string, code string) error {
	span := tracer.StartSpanFromContextMetadata(ctx, "SendVerificationEmail")
	defer span.Finish()

	to := []string{
		email,
	}

	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	subject := "Subject: DISLINKT Account Activation\r\n"

	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n"

	body := "<html><body><h1 style=\"font-size:2rem;color:black;\">Activate your account!</h1>" +
		"<p style=\"font-size:1rem;color:black;padding-bottom:1rem;\">Please click on button below to activate your account:</p>" +
		"<a style=\"padding:1rem; background-color:#800000; color:white; border: none; border-radius:5px; text-decoration: none; height: 2.5rem;text-align:center;font-size:1.2rem;\"" +
		"href=\"https://localhost:8083/activate/" + code + "\">" +
		"Activate" +
		"</a>" +
		"<p style=\"padding-top:3rem;color:black;\">DISLINKT</p></body></html>"

	message := []byte(subject + mime + body)

	auth := smtp.PlainAuth("", service.emailConfig.EmailUsername, service.emailConfig.EmailPassword, smtpHost)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, service.emailConfig.EmailUsername, to, message)
	if err != nil {
		fmt.Println(err)
	}

	return err
}
