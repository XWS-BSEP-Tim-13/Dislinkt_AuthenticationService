package application

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"github.com/google/uuid"
	"time"
)

type AuthenticationService struct {
	store             domain.UserStore
	jwtManager        JwtManager
	tokenStore        domain.ForgotPasswordTokenStore
	passwordlessStore domain.PasswordlessStore
	activemqService   ActiveMQ
}

func NewAuthenticationService(store domain.UserStore, tokenStore domain.ForgotPasswordTokenStore, passwordlessStore domain.PasswordlessStore, activemqService ActiveMQ) *AuthenticationService {
	return &AuthenticationService{
		store:             store,
		jwtManager:        *NewJwtManager(),
		tokenStore:        tokenStore,
		passwordlessStore: passwordlessStore,
		activemqService:   activemqService,
	}
}

func (service *AuthenticationService) Login(credentials *domain.Credentials) (*domain.Token, error) {
	dbUser, _ := service.store.GetByUsername((*credentials).Username)
	if (*dbUser).Username == "" {
		fmt.Println("Mail erorrr")
		err := errors.New("bad credentials")
		return nil, err
	}

	isPasswordCorrect := service.jwtManager.CheckPasswordHash((*credentials).Password, (*dbUser).Password)
	if !isPasswordCorrect {
		fmt.Println("Hash erorrr")
		err := errors.New("bad credentials")
		return nil, err
	}

	validToken, err := service.jwtManager.GenerateJWT((*dbUser).Username, (*dbUser).Role)
	if err != nil {
		fmt.Println("Jwt erorrr")
		err := errors.New("failed to generate token")
		return nil, err
	}

	var token domain.Token
	token.Username = (*dbUser).Username
	token.Role = (*dbUser).Role
	token.TokenString = validToken
	fmt.Println("Passed")
	return &token, nil
}

func (service *AuthenticationService) Register(user *domain.User) (*domain.User, error) {
	dbUser, _ := service.store.GetByUsername((*user).Username)
	if (*dbUser).Username != "" {
		err := errors.New("username already exists")
		return nil, err
	}

	var err error
	(*user).Password, err = service.jwtManager.GenerateHashPassword((*user).Password)
	if err != nil {
		err := errors.New("error in hashing password")
		return nil, err
	}

	newUser, err := service.store.Create(user)
	return newUser, err
}

func (service *AuthenticationService) SaveToken(email string) (*domain.ForgotPasswordToken, error) {
	var request = domain.ForgotPasswordToken{
		Email:        email,
		Token:        uuid.New().String(),
		ExpiringDate: time.Now().Local().Add(time.Hour * time.Duration(4)),
	}
	return service.tokenStore.Create(&request)
}

func (service *AuthenticationService) CheckIfTokenExists(token string) (*domain.ForgotPasswordToken, error) {
	return service.tokenStore.GetByToken(token)
}

func (service *AuthenticationService) ChangePassword(dto *domain.ChangePasswordDto, tokenObj *domain.ForgotPasswordToken) error {
	fmt.Printf("Changing password%s, %s \n", dto.Password, dto.ConfirmPassword)
	if dto.Password != dto.ConfirmPassword {
		err := errors.New("passwords do not match")
		return err
	}
	resp, err := service.store.GetByEmail(tokenObj.Email)
	if err != nil {
		return err
	}
	fmt.Printf("By email: %s\n", resp.Username)
	resp.Password, err = service.jwtManager.GenerateHashPassword(dto.Password)
	if err != nil {
		fmt.Printf("Error while generating password! \n")
		return err
	}
	err = service.store.UpdatePassword(resp)
	if err != nil {
		fmt.Printf("Error while changing password! \n")
		return err
	}
	service.tokenStore.Delete(tokenObj.ID)
	return nil
}

func (service *AuthenticationService) IsAuthorized(token *domain.Token) {
	//service.store.Create()
}

func (service *AuthenticationService) GetByEmail(email string) (*domain.User, error) {
	user, err := service.store.GetByEmail(email)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (service *AuthenticationService) CreatePasswordlessCredentials(credentials *domain.PasswordlessCredentials) (*domain.PasswordlessCredentials, error) {
	newCredentials, err := service.passwordlessStore.Create(credentials)
	return newCredentials, err
}

func (service *AuthenticationService) GenerateSecureCode(length int) (string, error) {
	otpChars := "1234567890"
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

func (service *AuthenticationService) HashSecureCode(code string) (string, error) {
	hashed, err := service.jwtManager.GenerateHashPassword(code)
	return hashed, err
}
func (service *AuthenticationService) SendApiToken(username string) error {
	user, err := service.store.GetByUsername(username)
	if err != nil {
		return errors.New("user not found")
	}

	token, err := service.jwtManager.GenerateJWT(user.Username, user.Role)
	if err != nil {
		return errors.New("error while creating token")
	}
	service.activemqService.Send(token)
	return nil
}
func (service *AuthenticationService) LoginWithCode(credentials *domain.PasswordlessCredentials) (*domain.Token, error) {
	dbUser, userError := service.GetByEmail(credentials.Email)
	if userError != nil {
		fmt.Println("no such user")
		return nil, userError
	}

	dbCredentials, credError := service.passwordlessStore.GetByEmail(credentials.Email)
	if credError != nil {
		fmt.Println("no such user passwordless")
		return nil, credError
	}

	if now := time.Now(); dbCredentials.ExpiringDate.Before(now) {
		err := errors.New("expired code")
		return nil, err
	}

	isCodeCorrect := service.jwtManager.CheckPasswordHash((*credentials).Code, (*dbCredentials).Code)
	if !isCodeCorrect {
		fmt.Println("bad code")
		err := errors.New("bad code")
		return nil, err
	}

	validToken, err := service.jwtManager.GenerateJWT((*dbUser).Username, (*dbUser).Role)
	if err != nil {
		fmt.Println("failed to generate token")
		err := errors.New("failed to generate token")
		return nil, err
	}

	var token domain.Token
	token.Username = (*dbUser).Username
	token.Role = (*dbUser).Role
	token.TokenString = validToken

	return &token, nil
}
