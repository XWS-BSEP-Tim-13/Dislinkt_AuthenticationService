package domain

type User struct {
	UserId   string `gorm:"unique"`
	Username string `gorm:"unique"`
	Password string
	Role     string
}

type Authentication struct {
	Username string `json:"email"`
	Password string `json:"password"`
}

type Token struct {
	Role        string `json:"role"`
	Username    string `json:"email"`
	TokenString string `json:"token"`
}
