package auth

import (
	"fmt"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
)

type EmailService struct {
	conn string
}

func NewEmailService(conn string) *EmailService {
	return &EmailService{
		conn: conn,
	}
}

func (s *EmailService) SendOTP(to, otp string) error {
	// For development, just log the OTP
	console.Debug(fmt.Sprintf("Sending OTP %s to %s", otp, to))
	return nil
}
