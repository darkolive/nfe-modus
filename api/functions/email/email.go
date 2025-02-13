package email

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hypermodeinc/modus/sdk/go/pkg/http"
)

type EmailRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Html    string   `json:"html"`
}

type Service struct{}

func NewService() *Service {
	return &Service{}
}

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
	title := "Your One-Time Password"
	content := fmt.Sprintf(`
		<div class="content">
			<p>Hello,</p>
			<p>Your one-time password (OTP) is:</p>
			<div class="highlight">%s</div>
			<p>This code will expire in 10 minutes.</p>
			<p>If you didn't request this code, please ignore this email.</p>
		</div>`, otp)

	htmlContent := fmt.Sprintf(baseTemplate, title, content)

	return s.sendEmail(to, title, htmlContent)
}

// SendWelcome sends a welcome email to new users
func (s *Service) SendWelcome(to string) error {
	title := "Welcome to Our Platform"
	content := `
		<div class="content">
			<p>Hello and welcome!</p>
			<p>We're excited to have you join our platform. Here are a few things you can do to get started:</p>
			<ul>
				<li>Complete your profile</li>
				<li>Explore our features</li>
				<li>Connect with others</li>
			</ul>
			<p>If you have any questions, feel free to reach out to our support team.</p>
		</div>`

	htmlContent := fmt.Sprintf(baseTemplate, title, content)

	return s.sendEmail(to, title, htmlContent)
}

// SendPasswordReset sends a password reset email
func (s *Service) SendPasswordReset(to, resetToken string) error {
	title := "Password Reset Request"
	content := fmt.Sprintf(`
		<div class="content">
			<p>Hello,</p>
			<p>We received a request to reset your password. Use the following code to proceed:</p>
			<div class="highlight">%s</div>
			<p>This code will expire in 1 hour.</p>
			<p>If you didn't request this reset, please ignore this email and ensure your account is secure.</p>
		</div>`, resetToken)

	htmlContent := fmt.Sprintf(baseTemplate, title, content)

	return s.sendEmail(to, title, htmlContent)
}

// sendEmail is a helper function to send emails via the Resend API
func (s *Service) sendEmail(to, subject, htmlContent string) error {
	emailReq := EmailRequest{
		From:    "info@darkolive.co.uk",
		To:      []string{to},
		Subject: subject,
		Html:    htmlContent,
	}

	// Debug the request body
	jsonBody, _ := json.MarshalIndent(emailReq, "", "  ")
	log.Printf("Request body: %s", string(jsonBody))

	// Create and send request to Resend API
	request := http.NewRequest("https://api.resend.com/emails/", &http.RequestOptions{
		Method: "POST",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: emailReq,
	})

	log.Printf("Making request to: %s", request.Url)
	log.Printf("Request headers: %v", request.Headers)

	response, err := http.Fetch(request)
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	// Check response status
	if !response.Ok() {
		responseText := response.Text()
		return fmt.Errorf("email service returned error: %d %s - %s", response.Status, response.StatusText, responseText)
	}

	var emailResponse struct {
		Id string `json:"id"`
	}
	response.JSON(&emailResponse)

	log.Printf("Email sent successfully. ID: %s", emailResponse.Id)
	return nil
}
