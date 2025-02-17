module nfe-modus

go 1.21

require (
	github.com/go-webauthn/webauthn v0.10.0
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/hypermodeinc/modus/sdk/go v0.0.0
	github.com/stretchr/testify v1.8.4
	golang.org/x/time v0.5.0
)

replace github.com/hypermodeinc/modus/sdk/go => ./vendor/github.com/hypermodeinc/modus/sdk/go