package domain

type ForgotPasswordTokenStore interface {
	Create(user *ForgotPasswordToken) (*ForgotPasswordToken, error)
	GetById(id int) (*ForgotPasswordToken, error)
	GetByToken(token string) (*ForgotPasswordToken, error)
}
