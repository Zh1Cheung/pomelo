package pomelo

import (
	"testing"
)

var (
	testVectors []struct {
		key       string
		random    string
		timestamp uint32
		payload   string
		expected  string
	}
)

// TestVector1 for testing encoding data to a valid pomelo token.
func TestVector1(t *testing.T) {
	testVectors = []struct {
		key       string
		random    string
		timestamp uint32
		payload   string
		expected  string
	}{
		{"supersecretkeyyoushouldnotcommit", "0102030405060708090a0b0c0102030405060708090a0b0c", 123206400, "Hello world!", "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"},
	}

}
