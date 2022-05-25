package util

import (
	"fmt"
	"github.com/go-playground/validator/v10"
	"regexp"
)

type GoValidator struct {
	Validator *validator.Validate
}

func NewGoValidator() *GoValidator {
	validator := &GoValidator{
		Validator: validator.New(),
	}

	validator.Validator.RegisterValidation("username", usernameValidator)
	validator.Validator.RegisterValidation("password", passwordValidator)

	return validator
}

func usernameValidator(fl validator.FieldLevel) bool {

	matches, err := regexp.MatchString("^[a-zA-Z\\d_.]+$", fl.Field().String())
	if err != nil {
		fmt.Println(err)
	}

	if !matches {
		return false
	}

	return true
}

func passwordValidator(fl validator.FieldLevel) bool {

	matches, err := regexp.MatchString("^(?=.*\\d)(?=.*[a-z])(?=.*[!@#$%^&*])(?=.*[A-Z])[\\da-zA-Z!@#$%^&*]{8,}$", fl.Field().String())
	if err != nil {
		fmt.Println(err)
	}

	if !matches {
		return false
	}

	return true

}
