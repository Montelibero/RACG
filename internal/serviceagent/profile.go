package serviceagent

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
)

type Profile struct {
	ServerID  string `json:"server_id"`
	PublicKey []byte `json:"public_key"`
}

func LoadProfile(path string) (Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}
	var profile Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		return Profile{}, err
	}
	if profile.ServerID == "" {
		return Profile{}, errors.New("profile server ID required")
	}
	if len(profile.PublicKey) != ed25519.PublicKeySize {
		return Profile{}, errors.New("profile requires an Ed25519 public key")
	}
	return profile, nil
}
