package email

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/http"
)

type EmailRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Html    string   `json:"html"`
	Text    string   `json:"text,omitempty"`
}

type Service struct {
	templates map[EmailType]string
	mu        sync.RWMutex
}

func NewService(conn string) *Service {
	s := &Service{
		templates: make(map[EmailType]string),
	}
	s.initTemplates()
	return s
}

func (s *Service) initTemplates() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Pre-compile templates
	s.templates[EmailTypeOTP] = fmt.Sprintf(baseTemplate, 
		"Your One-Time Password",
		`<div class="content">
			<p>Your one-time password is:</p>
			<div class="highlight">%s</div>
			<p>This code will expire in 10 minutes.</p>
		</div>`)

	s.templates[EmailTypeWelcome] = fmt.Sprintf(baseTemplate,
		"Welcome to Our Service",
		`<div class="content">
			<p>Thank you for joining our service!</p>
			<p>We're excited to have you on board.</p>
		</div>`)

	s.templates[EmailTypePassword] = fmt.Sprintf(baseTemplate,
		"Password Reset Request",
		`<div class="content">
			<p>Your password reset token is:</p>
			<div class="highlight">%s</div>
			<p>This token will expire in 1 hour.</p>
		</div>`)
}

// EmailType represents different types of emails
type EmailType string

const (
	EmailTypeOTP      EmailType = "OTP"
	EmailTypeWelcome  EmailType = "Welcome"
	EmailTypePassword EmailType = "Password"
)

// baseTemplate is the shared HTML structure for all emails
const baseTemplate = `
<!DOCTYPE html>
<html>
<head>
	<style>
		body {
			font-family: Arial, sans-serif;
			line-height: 1.6;
			color: #333;
		}
		.container {
			max-width: 600px;
			margin: 0 auto;
			padding: 20px;
		}
		.content {
			margin: 20px 0;
		}
		.highlight {
			font-size: 24px;
			font-weight: bold;
			color: #007bff;
			text-align: center;
			padding: 20px;
			margin: 20px 0;
			background-color: #f8f9fa;
			border-radius: 5px;
		}
		.footer {
			margin-top: 30px;
			padding-top: 20px;
			border-top: 1px solid #eee;
			font-size: 14px;
			color: #666;
		}
	</style>
</head>
<body>
	<div class="container">
		<h2>%s</h2>
		%s
		<div class="footer">
			<p>Best regards,<br>Your App Team</p>
		</div>
	</div>
</body>
</html>`

// SendOTP sends an OTP email
func (s *Service) SendOTP(to, otp string) error {
	s.mu.RLock()
	template := s.templates[EmailTypeOTP]
	s.mu.RUnlock()
	
	htmlContent := fmt.Sprintf(template, otp)
	return s.sendEmail(to, "Your One-Time Password", htmlContent)
}

// SendWelcome sends a welcome email
func (s *Service) SendWelcome(to string) error {
	s.mu.RLock()
	template := s.templates[EmailTypeWelcome]
	s.mu.RUnlock()
	
	return s.sendEmail(to, "Welcome to Our Service", template)
}

// SendPasswordReset sends a password reset email
func (s *Service) SendPasswordReset(to, resetToken string) error {
	s.mu.RLock()
	template := s.templates[EmailTypePassword]
	s.mu.RUnlock()
	
	htmlContent := fmt.Sprintf(template, resetToken)
	return s.sendEmail(to, "Password Reset Request", htmlContent)
}

// sendEmail is a helper function to send emails via the Resend API
func (s *Service) sendEmail(to, subject, htmlContent string) error {
	emailReq := EmailRequest{
		From:    "Dark Olive <info@darkolive.co.uk>",
		To:      []string{to},
		Subject: subject,
		Html:    htmlContent,
		Text:    "", // Optional plain text version
	}

	reqBody, err := json.Marshal(emailReq)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to marshal email request: %v", err))
		return fmt.Errorf("failed to marshal email request: %v", err)
	}

	console.Info(fmt.Sprintf("Sending email to: %s, subject: %s", to, subject))

	// Create request using Modus SDK's http package
	request := http.NewRequest("https://api.resend.com/emails/", &http.RequestOptions{
		Method: "POST",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: reqBody,
	})

	response, err := http.Fetch(request)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to send email - to: %s, subject: %s, error: %v", to, subject, err))
		return fmt.Errorf("failed to send email: %v", err)
	}

	if !response.Ok() {
		responseText := response.Text()
		console.Error(fmt.Sprintf("Email service error - status: %d, text: %s, response: %s, to: %s, subject: %s", 
			response.Status, 
			response.StatusText, 
			responseText,
			to,
			subject))
		return fmt.Errorf("email service returned error: %d %s - %s", response.Status, response.StatusText, responseText)
	}

	var emailResponse struct {
		Id string `json:"id"`
	}
	response.JSON(&emailResponse)

	console.Info(fmt.Sprintf("Email sent successfully - id: %s, to: %s, subject: %s", 
		emailResponse.Id,
		to,
		subject))

	return nil
}
