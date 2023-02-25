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
