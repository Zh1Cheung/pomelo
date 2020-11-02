package pomelo

import (
	"testing"
)

var (
	testVectors []struct {
		key       string
		nonce     string
		timestamp uint32
		payload   string
		expected  string
	}
)

// TestVector1 for testing encoding data to a valid pomelo token.
func TestVector1(t *testing.T) {
	testVectors = []struct {
		key       string
		nonce     string
		timestamp uint32
		payload   string
		expected  string
	}{
		{"supersecretkeyyoushouldnotcommit", "0102030405060708090a0b0c0102030405060708090a0b0c", 123206400, "Hello world!", "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"},
	}

	for _, table := range testVectors {
		p := NewPomelo(table.key)
		p.setNonce(table.nonce)
		p.setTimeStamp(table.timestamp)

		// Encode string.
		encoded, err := p.EncodeToString(table.payload)
		if err != nil {
			t.Errorf("%q", err)
		}
		if encoded != table.expected {
			t.Errorf("EncodeToString(\"%s\") = %s. got %s, expected %q", table.payload, encoded, encoded, table.expected)
		}

		// Decode string.
		decoded, err := p.DecodeToString(encoded)
		if err != nil {
			t.Errorf("%q", err)
		}
		if decoded != table.payload {
			t.Errorf("DecodeToString(\"%s\") = %s. got %s, expected %q", table.expected, decoded, decoded, table.expected)
		}
	}
}

// TestVector2 for testing encoding data to a valid pomelo token with a TTL.
func TestVector2(t *testing.T) {
	testVectors = []struct {
		key       string
		nonce     string
		timestamp uint32
		payload   string
		expected  string
	}{
		{"supersecretkeyyoushouldnotcommit", "0102030405060708090a0b0c0102030405060708090a0b0c", 123206400, "Hello world!", "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"},
	}

	for _, table := range testVectors {
		p := NewPomelo(table.key)
		p.setNonce(table.nonce)
		p.setTimeStamp(table.timestamp)

		// Encode string.
		encoded, err := p.EncodeToString(table.payload)
		if err != nil {
			t.Errorf("%q", err)
		}
		if encoded != table.expected {
			t.Errorf("EncodeToString(\"%s\") = %s. got %s, expected %q", table.payload, encoded, encoded, table.expected)
		}

		// Decode string with TTL. Should throw an error with no token encoded because it has expired.
		p.SetTTL(3600)
		decoded, derr := p.DecodeToString(encoded)
		if derr == nil {
			t.Errorf("%q", derr)
		}
		if decoded != "" {
			t.Errorf("DecodeToString(\"%s\") = %s. got %s, expected %q", table.expected, decoded, decoded, table.expected)
		}
	}
}

// TestGenerateToken for testing issuing pomelo tokens.
func TestGenerateToken(t *testing.T) {
	testVectors = []struct {
		key       string
		nonce     string
		timestamp uint32
		payload   string
		expected  string
	}{
		{"supersecretkeyyoushouldnotcommit", "0102030405060708090a0b0c0102030405060708090a0b0c", 123206400, "Hello world!", "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"},
	}

	for _, table := range testVectors {
		// Not generated with set timestamp.
		p := NewPomelo(table.key)

		// Encode string.
		encoded, err := p.EncodeToString(table.payload)
		if err != nil {
			t.Errorf("%q", err)
		}
		if encoded == table.expected {
			t.Errorf("EncodeToString(\"%s\") = %s. got %s, expected %q", table.payload, encoded, encoded, table.expected)
		}
	}
}

// TestInvalidEncodeString for testing errors when generating pomelo tokens.
func TestInvalidEncodeString(t *testing.T) {
	testVectors = []struct {
		key       string
		nonce     string
		timestamp uint32
		payload   string
		expected  string
	}{
		{"supersecretkeyyoushouldnotcommi", "0102030405060708090a0b0c0102030405060708090a0b0c", 123206400, "Hello world!", "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"}, // Invalid key

		{"supersecretkeyyoushouldnotcommi", "", 123206400, "Hello world!",
			"875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"}, // Invalid key + no nonce

	}

	for _, table := range testVectors {
		p := NewPomelo(table.key)

		_, err := p.EncodeToString(table.payload)
		if err == nil {
			t.Errorf("%q", err)
		}
	}
}

// TestInvalidDecodeString for testing errors when decoding pomelo tokens.
func TestInvalidDecodeString(t *testing.T) {
	testVectors = []struct {
		key       string
		nonce     string
		timestamp uint32
		payload   string
		expected  string
	}{
		{"supersecretkeyyoushouldnotcommit", "0102030405060708090a0b0c0102030405060708090a0b0c", 123206400, "Hello world!", "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0"}, // Invalid base62

		{"supersecretkeyyoushouldnotcommi", "", 123206400, "Hello world!",
			"875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsA"}, // Invalid key + Invalid base62.

		{"supersecretkeyyoushouldnotcommi", "0102030405060708090a0b0c0102030405060708090a0b0c", 123206400, "Hello world!", "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"}, // Invalid key

		{"supersecretkeyyoushouldnotcommit", "0102030405060708090a0b0c0102030405060708090a0b0c", 123206400, "Hello world!", "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLOZtQ0ekPHt8kJHQp0a"}, // Invalid malformed base62
	}

	for _, table := range testVectors {
		p := NewPomelo(table.key)

		_, err := p.DecodeToString(table.expected)
		if err == nil {
			t.Errorf("%q", err)
		}
	}
}
