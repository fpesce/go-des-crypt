package des_crypt

import "testing"

func TestDESCrypt(t *testing.T) {
	var desCryptTests = []struct {
		password [8]byte
		salt     [2]byte
		expected string
	}{
		{[8]byte{'f', 'o', 'o', 'b', 0, 0, 0, 0}, [2]byte{'a', 'r'}, "arlEKn0OzVJn."},
		{[8]byte{'t', 'e', 's', 't', 0, 0, 0, 0}, [2]byte{'P', 'Q'}, "PQl1.p7BcJRuM"},
		{[8]byte{'m', 'u', 'c', 'h', ' ', 'l', 'o', 'n'}, [2]byte{'x', 'x'}, "xxtHrOGVa3182"},
	}

	for _, tt := range desCryptTests {
		actual := DESCrypt(tt.password, tt.salt)
		if actual != tt.expected {
			t.Errorf("expected %s was not found in %s", tt.expected, actual)
		}
	}
}
