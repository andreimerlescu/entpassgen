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

func BenchmarkGenerateRandomPassword(b *testing.B) {
	length := 30
	for n := 0; n < b.N; n++ {
		password := generateRandomPassword(length)
		if len(password) != length {
			b.Errorf("Expected password length of %d, got %d", length, len(password))
		}
		if !containsValidCharacters(password) {
			b.Errorf("Password contains invalid characters: %s", password)
		}
	}
}

func TestCalculateEntropy(t *testing.T) {
	password := "dslkhflskhflkshlfkhslkhflkdshlfhsl"

	entropy := calculateEntropy(password)

	if entropy < 0 {
		t.Errorf("Entropy should not be negative, got %f", entropy)
	}
}

func BenchmarkCalculateEntropy(b *testing.B) {
	password := "dslkhflskhflkshlfkhslkhflkdshlfhsl"
	for i := 0; i < b.N; i++ {
		entropy := calculateEntropy(password)
		if entropy < 0 {
			b.Errorf("Entropy should not be negative, got %f", entropy)
		}
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

func BenchmarkParseEntropy(b *testing.B) {
	entropyStr := "9.32"
	expectedEntropy := 9.32

	for i := 0; i < b.N; i++ {
		entropy := parseEntropy(entropyStr)
		if entropy != expectedEntropy {
			b.Errorf("Expected entropy %f, got %f", expectedEntropy, entropy)
		}
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
