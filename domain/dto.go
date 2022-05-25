package domain

type Credentials struct {
	Username string `json:"email"`
	Password string `json:"password"`
}

type Token struct {
	Role        string `json:"role"`
	Username    string `json:"email"`
	TokenString string `json:"token"`
}

type ChangePasswordDto struct {
	Password        string `json:"password" validator:"required,password"`
	ConfirmPassword string `json:"confirmPassword" validator:"required"`
	Token           string `json:"token" validator:"required"`
}

type ActivatedAccount struct {
	Message  string `json:"message"`
	Role     string `json:"role"`
	Username string `json:"username"`
	Email    string `json:"email"`
}
