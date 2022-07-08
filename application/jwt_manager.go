package application

import (
	"context"
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/tracer"
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

func (manager *JwtManager) GenerateHashPassword(ctx context.Context, password string) (string, error) {
	span := tracer.StartSpanFromContextMetadata(ctx, "GenerateHashPassword")
	defer span.Finish()

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	fmt.Printf("%s, %s\n", password, bytes)
	return string(bytes), err
}

func (manager *JwtManager) GenerateJWT(ctx context.Context, username, role string) (string, error) {
	span := tracer.StartSpanFromContext(ctx, "GenerateJWT")
	defer span.Finish()

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

func (manager *JwtManager) GenerateJWTWithEmail(ctx context.Context, email, role string) (string, error) {
	span := tracer.StartSpanFromContext(ctx, "GenerateJWTWithEmail")
	defer span.Finish()

	var mySigningKey = []byte(manager.secretKey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["email"] = email
	claims["role"] = role
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(mySigningKey)

	if err != nil {
		fmt.Errorf("something Went Wrong: %s", err.Error())
		return "", err
	}
	return tokenString, nil
}

func (manager *JwtManager) CheckPasswordHash(ctx context.Context, password, hash string) bool {
	span := tracer.StartSpanFromContext(ctx, "CheckPasswordHash")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
