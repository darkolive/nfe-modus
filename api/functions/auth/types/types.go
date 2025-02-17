package types

import "time"

// DeviceCredential represents a device's authentication credentials
type DeviceCredential struct {
    DID          string    `json:"did"`
    UserHash     string    `json:"userHash"`
    DeviceID     string    `json:"deviceId"`
    PublicKey    string    `json:"publicKey"`
    LastSyncTime time.Time `json:"lastSyncTime"`
    IsVerified   bool      `json:"isVerified"`
    IsRevoked    bool      `json:"isRevoked"`
}
