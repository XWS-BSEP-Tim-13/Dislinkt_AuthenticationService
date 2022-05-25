package application

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type JwtManager struct {
	secretKey string
}

func NewJwtManager() *JwtManager {
	return &JwtManager{
		secretKey: "123456",
	}
}

func (manager *JwtManager) GenerateHashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	fmt.Printf("%s, %s\n", password, bytes)
	return string(bytes), err
}

func (manager *JwtManager) GenerateJWT(username, role string) (string, error) {
	var mySigningKey = []byte(manager.secretKey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["username"] = username
	claims["role"] = role
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(mySigningKey)

	if err != nil {
		fmt.Errorf("something Went Wrong: %s", err.Error())
		return "", err
	}
	return tokenString, nil
}

func (manager *JwtManager) CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
