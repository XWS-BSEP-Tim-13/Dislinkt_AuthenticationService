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
		Role:     "USER",
		Email:    "srdjansukovic@gmail.com",
	},
	{
		Username: "stefanljubovic1",
		ID:       2,
		Password: "$2a$10$3kfQZW0qQFJIlfDcadR9UOmPwUDDz4wwkcxxAi1aQmfqZqRxAU/FW",
		Role:     "USER",
		Email:    "bademailtest",
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
