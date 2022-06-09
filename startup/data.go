package startup

import (
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"github.com/google/uuid"
	"time"
)

var users = []*domain.User{
	{
		Username:  "stefanljubovic",
		Password:  "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		IsActive:  true,
		Role:      "USER",
		Email:     "stefanljubovic@gmail.com",
		MFASecret: "",
	},
	{
		Username:  "srdjansukovic",
		Password:  "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		IsActive:  true,
		Role:      "USER",
		Email:     "ljubovicstefan@gmail.com",
		MFASecret: "",
	},
	{
		Username:  "anagavrilovic",
		Password:  "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		IsActive:  true,
		Role:      "USER",
		Email:     "anagavrilovic@gmail.com",
		MFASecret: "",
	},
	{
		Username:  "marijakljestan",
		Password:  "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		IsActive:  true,
		Role:      "USER",
		Email:     "marijakljestan@gmail.com",
		MFASecret: "",
	},
	{
		Username:  "lenka",
		Password:  "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		IsActive:  true,
		Role:      "USER",
		Email:     "lenka@gmail.com",
		MFASecret: "",
	},
}

var tokens = []*domain.ForgotPasswordToken{
	{
		ID:           2,
		Token:        uuid.New().String(),
		Email:        "suki@gmail.com",
		ExpiringDate: time.Now(),
	},
}
