package main

import (
	"strings"
	"testing"
)

func TestGenerateRandomPassword(t *testing.T) {
	length := 30
	password := generateRandomPassword(length)

	if len(password) != length {
		t.Errorf("Expected password length of %d, got %d", length, len(password))
	}

	if !containsValidCharacters(password) {
		t.Errorf("Password contains invalid characters: %s", password)
	}
}

func TestCalculateEntropy(t *testing.T) {
	password := "dslkhflskhflkshlfkhslkhflkdshlfhsl"

	entropy := calculateEntropy(password)

	if entropy < 0 {
		t.Errorf("Entropy should not be negative, got %f", entropy)
	}
}

func TestParseEntropy(t *testing.T) {
	entropyStr := "9.32"
	expectedEntropy := 9.32

	entropy := parseEntropy(entropyStr)

	if entropy != expectedEntropy {
		t.Errorf("Expected entropy %f, got %f", expectedEntropy, entropy)
	}
}

func TestCalculateAverageEntropy(t *testing.T) {
	count := 1000
	avgEntropy, minEntropy, maxEntropy, _ := calculateAverageEntropy(count)

	if avgEntropy < 0 || minEntropy < 0 || maxEntropy < 0 {
		t.Errorf("Entropies should not be negative. Got avg: %f, min: %f, max: %f", avgEntropy, minEntropy, maxEntropy)
	}
}

// Helper function to check if the password contains valid characters
func containsValidCharacters(password string) bool {
	charset := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" + acceptableSymbols
	for _, char := range password {
		if !strings.ContainsRune(charset, char) {
			return false
		}
	}
	return true
}
