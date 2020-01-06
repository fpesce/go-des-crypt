/*
 *
 * Copyright 2019-2020 Francois Pesce
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package des_crypt

import (
	"testing"
	"unsafe"
)

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
	var output [14]byte
	for _, tt := range desCryptTests {
		saltbits := DESCryptGetSaltBits(tt.salt)
		r0, r1 := DESCryptRaw(tt.password, saltbits)

		DESCryptHashRaw(&output, tt.salt, r0, r1)
		actual := *(*string)(unsafe.Pointer(&output))
		for i := 0; i < len(tt.expected); i++ {
			if output[i] != 0 && output[i] != tt.expected[i] {
				t.Errorf("expected DESCryptRaw %s was not found in %s", tt.expected, actual)
			}
		}
		hashR0, hashR1 := DESCryptHashBytesRaw(string(output[:]))
		if r0 != hashR0 || r1 != hashR1 {
			t.Errorf("expected DESCryptHashBytesRaw failed %x,%x instead of %x,%x", hashR0, hashR1, r0, r1)
		}
	}
}

func BenchmarkDESCrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		DESCrypt([8]byte{'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z'}, [2]byte{'Z', 'Z'})
	}
}

func BenchmarkDESCryptRaw(b *testing.B) {
	saltbits := DESCryptGetSaltBits([2]byte{'Z', 'Z'})
	for i := 0; i < b.N; i++ {
		DESCryptRaw([8]byte{'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z'}, saltbits)
	}
}
