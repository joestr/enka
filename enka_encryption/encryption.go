//
// Copyright (c) 2023 Joel Strasser <joelstrasser1@gmail.com>
//
// Licensed under the EUPL-1.2 license.
//
// For the full license text consult the 'LICENSE' file from the repository.
//

package enka_encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"enka/pkcs7"
	"flag"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"io"
	"log"
	"strconv"
	"strings"
)

var encryptionAlgorithm string
var keyDerivationFunction string
var encryptionKeySalt string
var encryptionKey string
var plainText string
var verbose bool

func Encrypt(args []string, outLog *log.Logger, errorLog *log.Logger) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	fs.StringVar(&encryptionAlgorithm, "algo", "aes256cbc", "The encryption algorithm to use")
	fs.StringVar(&keyDerivationFunction, "kdf", "pbkdf2:650000:sha256", "The KDF to use")
	fs.StringVar(&encryptionKey, "key", "", "The encryption key")
	fs.StringVar(&encryptionKeySalt, "salt", "", "A salt for the KDF")
	fs.StringVar(&plainText, "text", "", "The string to encrypt")
	fs.BoolVar(&verbose, "verbose", false, "Set verbosity on")
	err := fs.Parse(args)
	if err != nil {
		return
	}

	if !isSupportedAlgo(encryptionAlgorithm) {
		errorLog.Fatalln(fmt.Sprintf("The specified algorithm \"%s\" is not supported", encryptionAlgorithm))
	}

	var isPbkdf2Used = false
	var pbkdf2IterationCount int
	var pbkdf2kdfHashFunction func() hash.Hash

	switch resolveKdfType(keyDerivationFunction) {
	case "pbkdf2":
		isPbkdf2Used = true
		pbkdf2IterationCount, pbkdf2kdfHashFunction = parsePbkdf2(keyDerivationFunction)
		break
	default:
		errorLog.Fatalln(fmt.Sprintf("The specified KDF \"%s\" is not supported", keyDerivationFunction))
	}

	var encryptionKeyBytes = []byte(encryptionKey)
	var encryptionKeySaltBytes []byte

	if encryptionKeySalt == "" {
		encryptionKeySaltBytes = make([]byte, 8)
		_, saltError := rand.Read(encryptionKeySaltBytes)
		if saltError != nil {
			panic(saltError)
		}
	} else {
		encryptionKeySaltBytes = []byte(encryptionKeySalt)
	}

	var derivativeKey []byte
	if isPbkdf2Used {
		derivativeKey = pbkdf2.Key(encryptionKeyBytes, encryptionKeySaltBytes, pbkdf2IterationCount, keylengthForAlgo(encryptionAlgorithm), pbkdf2kdfHashFunction)
	}

	if verbose {
		outLog.Println(fmt.Sprintf("key=%s", hex.EncodeToString(encryptionKeyBytes)))
		outLog.Println(fmt.Sprintf("salt=%s", hex.EncodeToString(encryptionKeySaltBytes)))
		outLog.Println(fmt.Sprintf("dk=%s", hex.EncodeToString(derivativeKey)))
	}

	var isAes256CbcUsed = false

	switch resolveAlgoType(encryptionAlgorithm) {
	case "aes256cbc":
		isAes256CbcUsed = true
		break
	}

	var plainBytes []byte
	var cipherBytes []byte
	var initalizationVector []byte

	if isAes256CbcUsed {
		block, cipherError := aes.NewCipher(derivativeKey)
		if cipherError != nil {
			panic(cipherError)
		}

		plainBytes = []byte(plainText)
		plainBytes, _ = pkcs7.Pkcs7pad(plainBytes, aes.BlockSize)

		cipherBytes = make([]byte, len(plainBytes))

		initalizationVector = make([]byte, aes.BlockSize)
		if _, ivError := io.ReadFull(rand.Reader, initalizationVector); ivError != nil {
			panic(ivError)
		}

		if verbose {
			outLog.Println(fmt.Sprintf("iv=%s", hex.EncodeToString(initalizationVector)))
		}

		mode := cipher.NewCBCEncrypter(block, initalizationVector)
		mode.CryptBlocks(cipherBytes, plainBytes)
	}

	fmt.Printf("%%enka%%v1%%%s%%%s%%%s%%%s%%%s\n", encryptionAlgorithm, keyDerivationFunction, base64.StdEncoding.EncodeToString(encryptionKeySaltBytes), base64.StdEncoding.EncodeToString(initalizationVector), base64.StdEncoding.EncodeToString(cipherBytes))
}

func keylengthForAlgo(algo string) int {
	switch algo {
	case "aes256cbc":
		return 32
		break
	}

	return 32
}

func isSupportedAlgo(algo string) bool {
	switch algo {
	case "aes256cbc":
		return true
		break
	}

	return false
}

func resolveAlgoType(algo string) string {
	switch algo {
	case "aes256cbc":
		return "aes256cbc"
		break
	}

	return ""
}

func resolveKdfType(kdf string) string {
	if strings.HasPrefix(kdf, "pbkdf2") {
		return "pbkdf2"
	}

	return ""
}

func parsePbkdf2(kdf string) (int, func() hash.Hash) {
	var params = strings.Split(kdf, ":")

	if len(params) != 3 {
		panic("The amount of arguments for PBKDF2 are invalid")
	}

	var iterCount, _ = strconv.Atoi(params[1])

	var hashFunction func() hash.Hash

	switch params[2] {
	case "sha1":
		hashFunction = sha1.New
	case "sha256":
		hashFunction = sha256.New
	case "sha256/224":
		hashFunction = sha256.New224
	case "sha512/384":
		hashFunction = sha512.New384
	case "sha512/224":
		hashFunction = sha512.New512_224
	case "sha512/256":
		hashFunction = sha512.New512_256
	case "sha512":
		hashFunction = sha512.New
	default:
		panic(fmt.Sprintf("The invalid hash algorithm %s for PBKDF2", kdf))
	}

	return iterCount, hashFunction
}
