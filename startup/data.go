package startup

import (
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"github.com/google/uuid"
	"time"
)

var users = []*domain.User{
	{
		Username: "stefanljubovic",
		ID:       1,
		Password: "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		IsActive: true,
		Role:     "USER",
	},
	{
		Username: "srdjansukovic",
		ID:       2,
		Password: "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		IsActive: true,
		Role:     "USER",
	},
	{
		Username: "anagavrilovic",
		ID:       3,
		Password: "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		IsActive: true,
		Role:     "USER",
	},
	{
		Username: "marijakljestan",
		ID:       4,
		Password: "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		IsActive: true,
		Role:     "USER",
	},
	{
		Username: "lenka",
		ID:       5,
		Password: "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		IsActive: true,
		Role:     "USER",
		Email:    "srdjansukovic@gmail.com",
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
