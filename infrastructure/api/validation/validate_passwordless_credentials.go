package validation

import (
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"github.com/go-playground/validator/v10"
)

// ValidatePasswordlessCredentials Validates passwordless credentials
func ValidatePasswordlessCredentials(passwordless *domain.PasswordlessCredentials) error {
	validate := validator.New()
	err := validate.Struct(passwordless)

	return err
}

// ValidateCode validates six digit code
func ValidateCode(code string) error {
	validate := validator.New()
	err := validate.Var(code, "numeric,len=6")

	return err
}

func PrintValidationErrors(err error) {
	for _, err := range err.(validator.ValidationErrors) {

		fmt.Println("Invalid value of field ", err.Field())
		fmt.Println()
	}
}
