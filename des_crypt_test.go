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
	for _, tt := range desCryptTests {
		output := make([]byte, 13)
		saltbits := DESCryptGetSaltBits(tt.salt)
		r0, r1 := DESCryptRaw(tt.password, saltbits)
		output[0] = tt.salt[0]
		output[1] = tt.salt[1]
		l := (r0 >> 8)
		output[2] = ascii64Bytes[(l>>18)&0x3f]
		output[3] = ascii64Bytes[(l>>12)&0x3f]
		output[4] = ascii64Bytes[(l>>6)&0x3f]
		output[5] = ascii64Bytes[l&0x3f]

		l = (r0 << 16) | ((r1 >> 16) & 0xffff)
		output[6] = ascii64Bytes[(l>>18)&0x3f]
		output[7] = ascii64Bytes[(l>>12)&0x3f]
		output[8] = ascii64Bytes[(l>>6)&0x3f]
		output[9] = ascii64Bytes[l&0x3f]

		l = r1 << 2
		output[10] = ascii64Bytes[(l>>12)&0x3f]
		output[11] = ascii64Bytes[(l>>6)&0x3f]
		output[12] = ascii64Bytes[l&0x3f]

		actual := *(*string)(unsafe.Pointer(&output))

		if actual != tt.expected {
			t.Errorf("expected DESCryptRaw %s was not found in %s", tt.expected, actual)
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
