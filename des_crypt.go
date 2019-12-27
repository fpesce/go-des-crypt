package des_crypt

import "unsafe"

var IP = [64]byte{58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7}

var inv_key_perm [64]byte
var key_perm = [56]byte{57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4}

var key_shifts = [16]byte{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}

var inv_comp_perm [56]byte
var comp_perm = [48]byte{14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32}

/*
 * No E box is used, as it's replaced by some ANDs, shifts, and ORs.
 */
var u_sbox [8][64]byte
var sbox = [8][64]byte{
	{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
	{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
	{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
	{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
	{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
	{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
	{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
	{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}

var un_pbox [32]byte
var pbox = [32]byte{16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25}

func bits32x(i, o int) uint32 {
	return 1 << (31 - (i + o))
}
func bits32(i int) uint32 {
	return bits32x(i, 0)
}
func bits28(i int) uint32 {
	return bits32x(i, 4)
}
func bits24(i int) uint32 {
	return bits32x(i, 8)
}
func bits8(i int) byte {
	return 1 << (7 - i)
}

var init_perm [64]byte
var final_perm [64]byte
var m_sbox [4][4096]byte
var psbox [4][256]uint32
var ip_maskl [8][256]uint32
var ip_maskr [8][256]uint32
var fp_maskl [8][256]uint32
var fp_maskr [8][256]uint32
var key_perm_maskl [8][128]uint32
var key_perm_maskr [8][128]uint32
var comp_maskl [8][128]uint32
var comp_maskr [8][128]uint32

const ascii64Bytes = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var ascii_to_bin = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 0, 0, 0, 0, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 0, 0, 0, 0, 0, 0, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func init() {
	var i, j, b, k, inbit, obit int
	var p, il, ir, fl, fr *uint32

	/*
	 * Invert the S-boxes, reordering the input bits.
	 */
	for i = 0; i < 8; i++ {
		for j = 0; j < 64; j++ {
			b = (j & 0x20) | ((j & 1) << 4) | ((j >> 1) & 0xf)
			u_sbox[i][j] = sbox[i][b]
		}
	}

	/*
	 * Convert the inverted S-boxes into 4 arrays of 8 bits.
	 * Each will handle 12 bits of the S-box input.
	 */
	for b = 0; b < 4; b++ {
		for i = 0; i < 64; i++ {
			for j = 0; j < 64; j++ {
				m_sbox[b][(i<<6)|j] = byte((u_sbox[(b << 1)][i] << 4) | u_sbox[(b<<1)+1][j])
			}
		}
	}

	/*
	 * Set up the initial & final permutations into a useful form, and
	 * initialise the inverted key permutation.
	 */
	for i = 0; i < 64; i++ {
		final_perm[i] = IP[i] - 1
		init_perm[final_perm[i]] = byte(i)
		inv_key_perm[i] = 255
	}

	/*
	 * Invert the key permutation and initialise the inverted key
	 * compression permutation.
	 */
	for i = 0; i < 56; i++ {
		inv_key_perm[key_perm[i]-1] = byte(i)
		inv_comp_perm[i] = 255
	}

	/*
	 * Invert the key compression permutation.
	 */
	for i = 0; i < 48; i++ {
		inv_comp_perm[comp_perm[i]-1] = byte(i)
	}

	/*
	 * Set up the OR-mask arrays for the initial and final permutations,
	 * and for the key initial and compression permutations.
	 */
	for k = 0; k < 8; k++ {
		for i = 0; i < 256; i++ {
			il = &ip_maskl[k][i]
			ir = &ip_maskr[k][i]
			fl = &fp_maskl[k][i]
			fr = &fp_maskr[k][i]
			for j = 0; j < 8; j++ {
				inbit = 8*k + j
				if byte(0) != (byte(i) & bits8(j)) {
					obit = int(init_perm[inbit])
					if obit < 32 {
						*il |= bits32(obit)
					} else {
						*ir |= bits32(obit - 32)
					}
					obit = int(final_perm[inbit])
					if obit < 32 {
						*fl |= bits32(obit)
					} else {
						*fr |= bits32(obit - 32)
					}
				}
			}
		}
		for i = 0; i < 128; i++ {
			il = &key_perm_maskl[k][i]
			ir = &key_perm_maskr[k][i]
			for j = 0; j < 7; j++ {
				inbit = 8*k + j
				if byte(0) != (byte(i) & bits8(j+1)) {
					obit = int(inv_key_perm[inbit])
					if obit == 255 {
						continue
					}
					if obit < 28 {
						*il |= bits28(obit)
					} else {
						*ir |= bits28(obit - 28)
					}
				}
			}
			il = &comp_maskl[k][i]
			ir = &comp_maskr[k][i]
			for j = 0; j < 7; j++ {
				inbit = 7*k + j
				if byte(0) != (byte(i) & bits8(j+1)) {
					obit = int(inv_comp_perm[inbit])
					if obit == 255 {
						continue
					}
					if obit < 24 {
						*il |= bits24(obit)
					} else {
						*ir |= bits24(obit - 24)
					}
				}
			}
		}
	}

	/*
	 * Invert the P-box permutation, and convert into OR-masks for
	 * handling the output of the S-box arrays setup above.
	 */
	for i = 0; i < 32; i++ {
		un_pbox[pbox[i]-1] = byte(i)
	}

	for b = 0; b < 4; b++ {
		for i = 0; i < 256; i++ {
			p = &psbox[b][i]
			for j = 0; j < 8; j++ {
				if byte(0) != (byte(i) & bits8(j)) {
					*p |= bits32(int(un_pbox[8*b+j]))
				}
			}
		}
	}
}

func leBswap32(x [8]byte) (uint32, uint32) {
	return uint32(x[0])<<24 | uint32(x[1])<<16 | uint32(x[2])<<8 | uint32(x[3]), uint32(x[4])<<24 | uint32(x[5])<<16 | uint32(x[6])<<8 | uint32(x[7])
}

const count = 25
const round = 16

func desSetKey(key [8]byte) (en_keysl, en_keysr [16]uint32) {
	var k0, k1 uint32
	var shifts int

	rawkey0, rawkey1 := leBswap32(key)
	/*
	 * Do key permutation and split into two 28-bit subkeys.
	 */
	k0 = key_perm_maskl[0][rawkey0>>25] | key_perm_maskl[1][(rawkey0>>17)&0x7f] | key_perm_maskl[2][(rawkey0>>9)&0x7f] | key_perm_maskl[3][(rawkey0>>1)&0x7f] | key_perm_maskl[4][rawkey1>>25] | key_perm_maskl[5][(rawkey1>>17)&0x7f] | key_perm_maskl[6][(rawkey1>>9)&0x7f] | key_perm_maskl[7][(rawkey1>>1)&0x7f]
	k1 = key_perm_maskr[0][rawkey0>>25] | key_perm_maskr[1][(rawkey0>>17)&0x7f] | key_perm_maskr[2][(rawkey0>>9)&0x7f] | key_perm_maskr[3][(rawkey0>>1)&0x7f] | key_perm_maskr[4][rawkey1>>25] | key_perm_maskr[5][(rawkey1>>17)&0x7f] | key_perm_maskr[6][(rawkey1>>9)&0x7f] | key_perm_maskr[7][(rawkey1>>1)&0x7f]
	/*
	 * Rotate subkeys and do compression permutation.
	 */
	shifts = 0
	for r := 0; r < round; r++ {
		var t0, t1 uint32

		shifts += int(key_shifts[r])

		t0 = (k0 << shifts) | (k0 >> (28 - shifts))
		t1 = (k1 << shifts) | (k1 >> (28 - shifts))

		en_keysl[r] = comp_maskl[0][(t0>>21)&0x7f] | comp_maskl[1][(t0>>14)&0x7f] | comp_maskl[2][(t0>>7)&0x7f] | comp_maskl[3][t0&0x7f] | comp_maskl[4][(t1>>21)&0x7f] | comp_maskl[5][(t1>>14)&0x7f] | comp_maskl[6][(t1>>7)&0x7f] | comp_maskl[7][t1&0x7f]
		en_keysr[r] = comp_maskr[0][(t0>>21)&0x7f] | comp_maskr[1][(t0>>14)&0x7f] | comp_maskr[2][(t0>>7)&0x7f] | comp_maskr[3][t0&0x7f] | comp_maskr[4][(t1>>21)&0x7f] | comp_maskr[5][(t1>>14)&0x7f] | comp_maskr[6][(t1>>7)&0x7f] | comp_maskr[7][t1&0x7f]
	}

	return en_keysl, en_keysr
}

func doDES(en_keysl, en_keysr [16]uint32, saltbits uint32, l_out, r_out *uint32) {
	/*
	 * l_out, and r_out are in pseudo-"big-endian" format.
	 */
	var l, r uint32
	var f, r48l, r48r uint32

	for i := 0; i < count; i++ {
		/*
		 * Do each round.
		 */
		for j := uint32(0); j < round; j++ {
			/*
			 * Expand R to 48 bits (simulate the E-box).
			 */
			r48l = ((r & 0x00000001) << 23) | ((r & 0xf8000000) >> 9) | ((r & 0x1f800000) >> 11) | ((r & 0x01f80000) >> 13) | ((r & 0x001f8000) >> 15)
			r48r = ((r & 0x0001f800) << 7) | ((r & 0x00001f80) << 5) | ((r & 0x000001f8) << 3) | ((r & 0x0000001f) << 1) | ((r & 0x80000000) >> 31)
			/*
			 * Do salting for crypt() and friends, and
			 * XOR with the permuted key.
			 */
			f = (r48l ^ r48r) & saltbits
			r48l ^= f ^ en_keysl[j]
			r48r ^= f ^ en_keysr[j]
			/*
			 * Do sbox lookups (which shrink it back to 32 bits)
			 * and do the pbox permutation at the same time.
			 */
			f = psbox[0][m_sbox[0][r48l>>12]] | psbox[1][m_sbox[1][r48l&0xfff]] | psbox[2][m_sbox[2][r48r>>12]] | psbox[3][m_sbox[3][r48r&0xfff]]
			/*
			 * Now that we've permuted things, complete f().
			 */
			f ^= l
			l = r
			r = f
		}
		r = l
		l = f
	}
	/*
	 * Do final permutation (inverse of IP).
	 */
	*l_out = fp_maskl[0][l>>24] | fp_maskl[1][(l>>16)&0xff] | fp_maskl[2][(l>>8)&0xff] | fp_maskl[3][l&0xff] | fp_maskl[4][r>>24] | fp_maskl[5][(r>>16)&0xff] | fp_maskl[6][(r>>8)&0xff] | fp_maskl[7][r&0xff]
	*r_out = fp_maskr[0][l>>24] | fp_maskr[1][(l>>16)&0xff] | fp_maskr[2][(l>>8)&0xff] | fp_maskr[3][l&0xff] | fp_maskr[4][r>>24] | fp_maskr[5][(r>>16)&0xff] | fp_maskr[6][(r>>8)&0xff] | fp_maskr[7][r&0xff]
}

func setupSalt(salt uint32) uint32 {
	var obit, saltbit, saltbits uint32

	saltbit = 1
	obit = 0x800000
	for i := 0; i < 24; i++ {
		if (salt & saltbit) != 0 {
			saltbits |= obit
		}
		saltbit <<= 1
		obit >>= 1
	}

	return saltbits
}

func DESCryptGetSaltBits(setting [2]byte) uint32 {
	return setupSalt(uint32(ascii_to_bin[setting[1]])<<6 | uint32(ascii_to_bin[setting[0]]))
}

func DESCryptRaw(key [8]byte, saltbits uint32) (r0, r1 uint32) {
	/* shifting each character up by one bit */
	for i := 0; i < 8; i++ {
		if 0 != key[i] {
			key[i] <<= 1
		}
	}
	en_keysl, en_keysr := desSetKey(key)
	doDES(en_keysl, en_keysr, saltbits, &r0, &r1)

	return r0, r1
}

func DESCrypt(key [8]byte, setting [2]byte) string {
	output := make([]byte, 13)

	saltbits := DESCryptGetSaltBits(setting)
	r0, r1 := DESCryptRaw(key, saltbits)
	output[0] = setting[0]
	output[1] = setting[1]
	/*
	 * Now encode the result...
	 */
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

	return *(*string)(unsafe.Pointer(&output))
}
