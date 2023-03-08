//
// Copyright (c) 2023 Joel Strasser <joelstrasser1@gmail.com>
//
// Licensed under the EUPL-1.2 license.
//
// For the full license text consult the 'LICENSE' file from the repository.
//

package main

import (
	"enka/enka_decryption"
	"enka/enka_encryption"
	"testing"
)

func TestDefaultEncryption(t *testing.T) {
	args := []string{"--algo", "aes256cbc", "--kdf", "pbkdf2:650000:sha256", "--key", "1234", "--text", "abcd"}
	enka_encryption.Encrypt(args, nil, nil)
}

func TestDefaultDecryption(t *testing.T) {
	args := []string{"--string", "%enka%v1%aes256cbc%pbkdf2:650000:sha256%rhGye/PFC9U=%GiGjGRW2BrQxYdiY69Dstg==%BVeCM81SXQqSwVuMjRyIIQ==", "--key", "1234"}
	enka_decryption.Decrypt(args, nil, nil)
}

func TestAes192CbcArgon2IdDefaultEncryption(t *testing.T) {
	args := []string{"--algo", "aes192cbc", "--kdf", "argon2id:1:65536:4", "--key", "1234", "--text", "abcd"}
	enka_encryption.Encrypt(args, nil, nil)
}

func TestAes192CbcArgon2IdDefaultDecryption(t *testing.T) {
	args := []string{"--string", "%enka%v1%aes192cbc%argon2id:1:65536:4%2eUjGF4/s1w=%gDZyDGfCwaX8y45D8heutQ==%tGwbFcnfIWDZkGvtWdCffQ==", "--key", "1234"}
	enka_decryption.Decrypt(args, nil, nil)
}

func TestAes128CbcPbkdf2Iter20Sha512256Encryption(t *testing.T) {
	args := []string{"--algo", "aes128cbc", "--kdf", "pbkdf2:20:sha512/256", "--key", "1234", "--text", "abcd"}
	enka_encryption.Encrypt(args, nil, nil)
}

func TestAes128CbcPbkdf2Iter20Sha512256Decryption(t *testing.T) {
	args := []string{"--string", "%enka%v1%aes128cbc%pbkdf2:20:sha512/256%13RKiPraGzc=%acl2D57zwrHrMm7xb72ZZg==%XYT8Dt8WedI9ZpBE51l0MA==", "--key", "1234"}
	enka_decryption.Decrypt(args, nil, nil)
}
