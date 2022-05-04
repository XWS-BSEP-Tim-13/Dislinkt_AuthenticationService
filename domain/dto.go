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
