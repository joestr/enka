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
	"github.com/enceve/crypto/camellia"
	"golang.org/x/crypto/argon2"
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

	if encryptionKey == "" {
		errorLog.Fatalln("Encryption key cannot be empty")
	}

	if plainText == "" {
		errorLog.Fatalln("Text cannot be empty")
	}

	var isPbkdf2Used = false
	var pbkdf2IterationCount int
	var pbkdf2kdfHashFunction func() hash.Hash
	var isArgon2IdUsed = false
	var argon2IdTime int
	var argon2IdMemory int
	var argon2IdThreads int

	switch resolveKdfType(keyDerivationFunction) {
	case "pbkdf2":
		isPbkdf2Used = true
		pbkdf2IterationCount, pbkdf2kdfHashFunction = parsePbkdf2(keyDerivationFunction)
		break
	case "argon2id":
		isArgon2IdUsed = true
		argon2IdTime, argon2IdMemory, argon2IdThreads = parseArgon2Id(keyDerivationFunction)
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
	} else if isArgon2IdUsed {
		derivativeKey = argon2.IDKey(encryptionKeyBytes, encryptionKeySaltBytes, uint32(argon2IdTime), uint32(argon2IdMemory), uint8(argon2IdThreads), uint32(keylengthForAlgo(encryptionAlgorithm)))
	}

	if verbose {
		outLog.Println(fmt.Sprintf("key=%s", hex.EncodeToString(encryptionKeyBytes)))
		outLog.Println(fmt.Sprintf("salt=%s", hex.EncodeToString(encryptionKeySaltBytes)))
		outLog.Println(fmt.Sprintf("dk=%s", hex.EncodeToString(derivativeKey)))
	}

	var isAes256CbcUsed = false
	var isAes192CbcUsed = false
	var isAes128CbcUsed = false
	var isCamellia128Used = false
	var isCamellia192Used = false
	var isCamellia256Used = false

	switch resolveAlgoType(encryptionAlgorithm) {
	case "aes256cbc":
		isAes256CbcUsed = true
		break
	case "aes192cbc":
		isAes192CbcUsed = true
		break
	case "aes128cbc":
		isAes128CbcUsed = true
		break
	case "camellia128":
		isCamellia128Used = true
		break
	case "camellia192":
		isCamellia192Used = true
		break
	case "camellia256":
		isCamellia256Used = true
		break
	}

	var plainBytes []byte
	var cipherBytes []byte
	var initializationVector []byte

	if isAes256CbcUsed || isAes192CbcUsed || isAes128CbcUsed {
		block, cipherError := aes.NewCipher(derivativeKey)
		if cipherError != nil {
			panic(cipherError)
		}

		plainBytes = []byte(plainText)
		plainBytes, _ = pkcs7.Pkcs7pad(plainBytes, aes.BlockSize)

		cipherBytes = make([]byte, len(plainBytes))

		initializationVector = make([]byte, aes.BlockSize)
		if _, ivError := io.ReadFull(rand.Reader, initializationVector); ivError != nil {
			panic(ivError)
		}

		if verbose {
			outLog.Println(fmt.Sprintf("iv=%s", hex.EncodeToString(initializationVector)))
		}

		mode := cipher.NewCBCEncrypter(block, initializationVector)
		mode.CryptBlocks(cipherBytes, plainBytes)
	}

	if isCamellia256Used || isCamellia192Used || isCamellia128Used {
		block, cipherError := camellia.NewCipher(derivativeKey)
		if cipherError != nil {
			panic(cipherError)
		}

		plainBytes = []byte(plainText)
		plainBytes, _ = pkcs7.Pkcs7pad(plainBytes, aes.BlockSize)

		cipherBytes = make([]byte, len(plainBytes))

		initializationVector = make([]byte, aes.BlockSize)

		if _, ivError := io.ReadFull(rand.Reader, initializationVector); ivError != nil {
			panic(ivError)
		}

		if verbose {
			outLog.Println(fmt.Sprintf("iv=%s", hex.EncodeToString(initializationVector)))
		}

		mode := cipher.NewCBCEncrypter(block, initializationVector)
		mode.CryptBlocks(cipherBytes, plainBytes)
	}

	fmt.Printf("%%enka%%v1%%%s%%%s%%%s%%%s%%%s\n", encryptionAlgorithm, keyDerivationFunction, base64.StdEncoding.EncodeToString(encryptionKeySaltBytes), base64.StdEncoding.EncodeToString(initializationVector), base64.StdEncoding.EncodeToString(cipherBytes))
}

func keylengthForAlgo(algo string) int {
	switch algo {
	case "aes256cbc":
		return 32
		break
	case "aes192cbc":
		return 24
		break
	case "aes128cbc":
		return 16
		break
	case "camellia256":
		return 32
		break
	case "camellia192":
		return 24
		break
	case "camellia128":
		return 16
		break
	}

	return 32
}

func isSupportedAlgo(algo string) bool {
	switch algo {
	case "aes256cbc":
		return true
		break
	case "aes192cbc":
		return true
		break
	case "aes128cbc":
		return true
		break
	case "camellia256":
		return true
		break
	case "camellia192":
		return true
		break
	case "camellia128":
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
	case "aes192cbc":
		return "aes192cbc"
		break
	case "aes128cbc":
		return "aes128cbc"
		break
	case "camellia256":
		return "camellia256"
		break
	case "camellia192":
		return "camellia192"
		break
	case "camellia128":
		return "camellia128"
		break
	}

	return ""
}

func resolveKdfType(kdf string) string {
	if strings.HasPrefix(kdf, "pbkdf2") {
		return "pbkdf2"
	} else if strings.HasPrefix(kdf, "argon2id") {
		return "argon2id"
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

func parseArgon2Id(kdf string) (int, int, int) {
	var params = strings.Split(kdf, ":")

	if len(params) != 4 {
		panic("The amount of arguments for Argon2id are invalid")
	}

	var time, _ = strconv.Atoi(params[1])
	var memory, _ = strconv.Atoi(params[2])
	var threads, _ = strconv.Atoi(params[3])

	return time, memory, threads
}
