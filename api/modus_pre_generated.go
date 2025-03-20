// Code generated by Modus. DO NOT EDIT.

package main

import (
	"nfe-modus/api/functions/auth"
	"nfe-modus/api/functions/user"
	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
)

//go:export generateOTP
func __modus_GenerateOTP(req *auth.GenerateOTPRequest) *auth.GenerateOTPResponse {
	r0, err := GenerateOTP(req)
	if err != nil {
		console.Error(err.Error())
	}
	return r0
}

//go:export verifyOTP
func __modus_VerifyOTP(req *auth.VerifyOTPRequest) *auth.VerifyOTPResponse {
	r0, err := VerifyOTP(req)
	if err != nil {
		console.Error(err.Error())
	}
	return r0
}

//go:export getUserTimestamps
func __modus_GetUserTimestamps(req *user.GetUserTimestampsInput) *user.UserTimestamps {
	r0, err := GetUserTimestamps(req)
	if err != nil {
		console.Error(err.Error())
	}
	return r0
}

//go:export registerWebAuthn
func __modus_RegisterWebAuthn(req *auth.WebAuthnRegistrationRequest) *auth.WebAuthnRegistrationResponse {
	r0, err := RegisterWebAuthn(req)
	if err != nil {
		console.Error(err.Error())
	}
	return r0
}

//go:export verifyWebAuthn
func __modus_VerifyWebAuthn(req *auth.WebAuthnVerificationRequest) *auth.WebAuthnVerificationResponse {
	r0, err := VerifyWebAuthn(req)
	if err != nil {
		console.Error(err.Error())
	}
	return r0
}

//go:export registerPassphrase
func __modus_RegisterPassphrase(req *auth.RegisterPassphraseRequest) *auth.RegisterPassphraseResponse {
	r0, err := RegisterPassphrase(req)
	if err != nil {
		console.Error(err.Error())
	}
	return r0
}

//go:export signinPassphrase
func __modus_SigninPassphrase(req *auth.SigninPassphraseRequest) *auth.SigninPassphraseResponse {
	r0, err := SigninPassphrase(req)
	if err != nil {
		console.Error(err.Error())
	}
	return r0
}

//go:export recoveryPassphrase
func __modus_RecoveryPassphrase(req *auth.RecoveryPassphraseRequest) *auth.RecoveryPassphraseResponse {
	r0, err := RecoveryPassphrase(req)
	if err != nil {
		console.Error(err.Error())
	}
	return r0
}

//go:export resetPassphrase
func __modus_ResetPassphrase(req *auth.ResetPassphraseRequest) *auth.ResetPassphraseResponse {
	r0, err := ResetPassphrase(req)
	if err != nil {
		console.Error(err.Error())
	}
	return r0
}

//go:export updateUserDetails
func __modus_UpdateUserDetails(req *auth.UserDetailsRequest) *auth.UserDetailsResponse {
	r0, err := UpdateUserDetails(req)
	if err != nil {
		console.Error(err.Error())
	}
	return r0
}

//go:export registerUserDetails
func __modus_RegisterUserDetails(req *auth.RegisterUserDetailsRequest) *auth.UserDetailsResponse {
	r0, err := RegisterUserDetails(req)
	if err != nil {
		console.Error(err.Error())
	}
	return r0
}

