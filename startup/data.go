package startup

import (
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/domain"
	"github.com/google/uuid"
	"time"
)

var users = []*domain.User{
	{
		Username: "stefanljubovic",
		Password: "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		IsActive: true,
		Role:     "USER",
		Email:    "stefanljubovic@gmail.com",
	},
	{
		Username: "srdjansukovic",
		Password: "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		IsActive: true,
		Role:     "USER",
		Email:    "ljubovicstefan@gmail.com",
	},
	{
		Username: "stefanljubovic1",
		ID:       2,
		Password: "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		Role:     "USER",
		Email:    "bademailtest",
	},
	{
		Username: "anagavrilovic",
		Password: "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		IsActive: true,
		Role:     "USER",
		Email:    "anagavrilovic@gmail.com",
	},
	{
		Username: "marijakljestan",
		Password: "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		IsActive: true,
		Role:     "USER",
		Email:    "marijakljestan@gmail.com",
	},
	{
		Username: "lenka",
		Password: "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		IsActive: true,
		Role:     "USER",
		Email:    "lenka@gmail.com",
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
