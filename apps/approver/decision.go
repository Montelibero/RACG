package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/itolstov/racg/internal/approval"
)

func verifiedRequest(profile ServerProfile, data []byte) (approval.SignedRequest, string, error) {
	var signed approval.SignedRequest
	if err := json.Unmarshal(data, &signed); err != nil {
		return approval.SignedRequest{}, "", fmt.Errorf("decode signed request: %w", err)
	}
	if err := approval.VerifyRequest(signed, profile.ServerID, ed25519.PublicKey(profile.PublicKey)); err != nil {
		return approval.SignedRequest{}, "", err
	}
	digest, err := approval.RequestDigest(signed.Request)
	if err != nil {
		return approval.SignedRequest{}, "", err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, signed.Request.Operation, "", "  "); err != nil {
		return approval.SignedRequest{}, "", err
	}
	text := fmt.Sprintf("Server: %s\nAgent: %s\nRequest: %s\nDigest: %s\n\nSigned operation:\n%s",
		strconv.QuoteToASCII(signed.Request.ServerID), strconv.QuoteToASCII(signed.Request.ClientID), strconv.QuoteToASCII(signed.Request.RequestID), digest, pretty.String())
	return signed, visibleText(text), nil
}

func verifiedPreview(profile ServerProfile, data []byte) (string, error) {
	_, text, err := verifiedRequest(profile, data)
	return text, err
}

func decisionEnvelope(request approval.Request, deviceID, action string, validUntil time.Time, key *DeviceKey) (string, error) {
	if key == nil || len(key.Private) != ed25519.PrivateKeySize || key.ID == "" {
		return "", errors.New("signing key is locked")
	}
	if deviceID != key.ID {
		return "", errors.New("request is not bound to the unlocked device")
	}
	signed, err := approval.SignDecision(request, deviceID, action, nil, validUntil, key.Private)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err != nil {
		return "", err
	}
	return pretty.String(), nil
}
