package obfuscator

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestBasicObfuscationCycle(t *testing.T) {
	passphrase := []byte("testPassphrase123")
	obfuscator := New(passphrase)

	originalText := "Hello, World!"
	obfuscated, err := obfuscator.Obfuscate(originalText)
	if err != nil {
		t.Fatalf("Failed to obfuscate: %v", err)
	}

	if obfuscated == originalText {
		t.Error("Obfuscated text should be different from original")
	}

	unobfuscated, err := obfuscator.Unobfuscate(obfuscated)
	if err != nil {
		t.Fatalf("Failed to unobfuscate: %v", err)
	}

	if unobfuscated != originalText {
		t.Errorf("Expected %q, got %q", originalText, unobfuscated)
	}
}

func TestVariousInputs(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"simple text", "Simple text"},
		{"special chars", "Special chars: !@#$%^&*()"},
		{"unicode", "Unicode: 你好，世界！"},
		{"long text", "Very long text that is more than just a few words and contains multiple sentences. " +
			"It also has some numbers 12345 and special characters !@#$%."},
	}

	obfuscator := New([]byte("testPassphrase123"))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			obfuscated, err := obfuscator.Obfuscate(tc.input)
			if err != nil {
				t.Fatalf("Failed to obfuscate: %v", err)
			}

			unobfuscated, err := obfuscator.Unobfuscate(obfuscated)
			if err != nil {
				t.Fatalf("Failed to unobfuscate: %v", err)
			}

			if unobfuscated != tc.input {
				t.Errorf("Expected %q, got %q", tc.input, unobfuscated)
			}
		})
	}
}

func TestRandomization(t *testing.T) {
	obfuscator := New([]byte("testPassphrase123"))
	input := "Same input text"

	first, err := obfuscator.Obfuscate(input)
	if err != nil {
		t.Fatalf("Failed first obfuscation: %v", err)
	}

	second, err := obfuscator.Obfuscate(input)
	if err != nil {
		t.Fatalf("Failed second obfuscation: %v", err)
	}

	if first == second {
		t.Error("Expected different obfuscated outputs for same input")
	}
}

func TestCustomSaltLength(t *testing.T) {
	customSaltLength := uint8(16)
	obfuscator := New([]byte("testPassphrase123"), WithSaltLength(customSaltLength))

	obfuscated, err := obfuscator.Obfuscate("Test text")
	if err != nil {
		t.Fatalf("Failed to obfuscate: %v", err)
	}

	parts := strings.Split(obfuscated, DefaultSeparator)
	if len(parts) != 5 { // Including empty first part
		t.Fatalf("Expected 5 parts, got %d", len(parts))
	}

	saltBytes, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("Failed to decode salt: %v", err)
	}

	if len(saltBytes) != int(customSaltLength) {
		t.Errorf("Expected salt length %d, got %d", customSaltLength, len(saltBytes))
	}
}

func TestCustomSeparator(t *testing.T) {
	customSeparator := "#"
	obfuscator := New([]byte("testPassphrase123"), WithSeparator(customSeparator))

	input := "Test text"
	obfuscated, err := obfuscator.Obfuscate(input)
	if err != nil {
		t.Fatalf("Failed to obfuscate: %v", err)
	}

	if !strings.HasPrefix(obfuscated, customSeparator) {
		t.Error("Expected obfuscated text to start with separator")
	}

	separatorCount := strings.Count(obfuscated, customSeparator)
	if separatorCount != 4 {
		t.Errorf("Expected 4 separators, got %d", separatorCount)
	}

	parts := strings.Split(obfuscated, customSeparator)
	if len(parts) != 5 { // Including empty first part
		t.Errorf("Expected 5 parts, got %d", len(parts))
	}

	if parts[1] != Version {
		t.Errorf("Expected version %s, got %s", Version, parts[1])
	}

	unobfuscated, err := obfuscator.Unobfuscate(obfuscated)
	if err != nil {
		t.Fatalf("Failed to unobfuscate: %v", err)
	}

	if unobfuscated != input {
		t.Errorf("Expected %q, got %q", input, unobfuscated)
	}
}

func TestWrongPassphrase(t *testing.T) {
	originalObfuscator := New([]byte("correctPassphrase"))
	wrongObfuscator := New([]byte("wrongPassphrase"))

	input := "Secret message"
	obfuscated, err := originalObfuscator.Obfuscate(input)
	if err != nil {
		t.Fatalf("Failed to obfuscate: %v", err)
	}

	_, err = wrongObfuscator.Unobfuscate(obfuscated)
	if err == nil {
		t.Error("Expected error when using wrong passphrase")
	}
}

func TestInvalidObfuscatedText(t *testing.T) {
	obfuscator := New([]byte("testPassphrase123"))

	invalidInputs := []string{
		"invalid$format$string",
		"$invalid$format",
		"$o1$not$enough$parts",
		"",
	}

	for _, input := range invalidInputs {
		_, err := obfuscator.Unobfuscate(input)
		if err == nil {
			t.Errorf("Expected error for invalid input: %q", input)
		}
	}
}

func TestUnsupportedVersion(t *testing.T) {
	obfuscator := New([]byte("testPassphrase123"))
	invalidVersionText := "$o2$salt$iv$ciphertext"

	_, err := obfuscator.Unobfuscate(invalidVersionText)
	if !errors.Is(err, ErrorUnsupportedVersion) {
		t.Errorf("Expected UnsupportedVersion error, got: %v", err)
	}
}

func TestMultipleOptions(t *testing.T) {
	customSaltLength := uint8(16)
	customSeparator := "#"
	obfuscator := New([]byte("testPassphrase123"),
		WithSaltLength(customSaltLength),
		WithSeparator(customSeparator))

	input := "Test with multiple options"
	obfuscated, err := obfuscator.Obfuscate(input)
	if err != nil {
		t.Fatalf("Failed to obfuscate: %v", err)
	}

	if !strings.Contains(obfuscated, customSeparator) {
		t.Error("Expected custom separator in output")
	}

	parts := strings.Split(obfuscated, customSeparator)
	saltBytes, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("Failed to decode salt: %v", err)
	}

	if len(saltBytes) != int(customSaltLength) {
		t.Errorf("Expected salt length %d, got %d", customSaltLength, len(saltBytes))
	}

	unobfuscated, err := obfuscator.Unobfuscate(obfuscated)
	if err != nil {
		t.Fatalf("Failed to unobfuscate: %v", err)
	}

	if unobfuscated != input {
		t.Errorf("Expected %q, got %q", input, unobfuscated)
	}
}

func TestNilPassphrase(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic with nil passphrase")
		}
	}()

	New(nil)
}

// Benchmark tests
func BenchmarkObfuscate(b *testing.B) {
	obfuscator := New([]byte("benchmarkPassphrase"))
	input := "This is a test string for benchmarking"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := obfuscator.Obfuscate(input)
		if err != nil {
			b.Fatalf("Failed to obfuscate: %v", err)
		}
	}
}

func BenchmarkUnobfuscate(b *testing.B) {
	obfuscator := New([]byte("benchmarkPassphrase"))
	input := "This is a test string for benchmarking"
	obfuscated, err := obfuscator.Obfuscate(input)
	if err != nil {
		b.Fatalf("Failed to setup benchmark: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := obfuscator.Unobfuscate(obfuscated)
		if err != nil {
			b.Fatalf("Failed to unobfuscate: %v", err)
		}
	}
}