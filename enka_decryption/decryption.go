//
// Copyright (c) 2023 Joel Strasser <joelstrasser1@gmail.com>
//
// Licensed under the EUPL-1.2 license.
//
// For the full license text consult the 'LICENSE' file from the repository.
//

package enka_decryption

import (
	"crypto/aes"
	"crypto/cipher"
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
	"log"
	"strconv"
	"strings"
)

var enkaString string
var encryptionKey string
var verbose bool

func Decrypt(args []string, outLog *log.Logger, errorLog *log.Logger) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	fs.StringVar(&enkaString, "string", "", "The 'enka' string to parse and decrypt")
	fs.StringVar(&encryptionKey, "key", "", "The decryption key")
	fs.BoolVar(&verbose, "verbose", false, "Set verbosity on")
	err := fs.Parse(args)
	if err != nil {
		return
	}

	var splittedEnkaString = strings.Split(enkaString, "%")

	if len(splittedEnkaString) == 0 {
		errorLog.Fatalln("String has an invalid format")
	}

	if splittedEnkaString[1] != "enka" {
		errorLog.Fatalln("String is not an 'enka' string")
	}

	if splittedEnkaString[2] != "v1" {
		errorLog.Fatalln("This version of an 'enka' string is not supported")
	}

	if encryptionKey == "" {
		errorLog.Fatalln("Decryption key cannot be empty")
	}

	if len(splittedEnkaString[3:]) != 5 {
		errorLog.Fatalln(fmt.Sprintf("Five sections are required; got %s", len(splittedEnkaString[2:])))
	}

	var encryptionKeyBytes = []byte(encryptionKey)
	var encryptionAlgorithm = splittedEnkaString[3]
	var keyDerivationFunction = splittedEnkaString[4]
	var encryptionKeySaltBytes, _ = base64.RawStdEncoding.DecodeString(strings.Replace(splittedEnkaString[5], "=", "", -1))
	var initializationVector, _ = base64.RawStdEncoding.DecodeString(strings.Replace(splittedEnkaString[6], "=", "", -1))
	var cipherBytes, _ = base64.RawStdEncoding.DecodeString(strings.Replace(splittedEnkaString[7], "=", "", -1))

	if !isSupportedAlgo(encryptionAlgorithm) {
		errorLog.Fatalln(fmt.Sprintf("The specified algorithm \"%s\" is not supported", encryptionAlgorithm))
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

	var derivativeKey []byte

	if isPbkdf2Used {
		derivativeKey = pbkdf2.Key(encryptionKeyBytes, encryptionKeySaltBytes, pbkdf2IterationCount, keyLengthForAlgo(encryptionAlgorithm), pbkdf2kdfHashFunction)
	} else if isArgon2IdUsed {
		derivativeKey = argon2.IDKey(encryptionKeyBytes, encryptionKeySaltBytes, uint32(argon2IdTime), uint32(argon2IdMemory), uint8(argon2IdThreads), uint32(keyLengthForAlgo(encryptionAlgorithm)))
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
	var plainText string

	if isAes256CbcUsed || isAes192CbcUsed || isAes128CbcUsed {
		block, cipherError := aes.NewCipher(derivativeKey)
		if cipherError != nil {
			panic(cipherError)
		}

		plainBytes = make([]byte, len(cipherBytes))

		mode := cipher.NewCBCDecrypter(block, initializationVector)
		mode.CryptBlocks(plainBytes, cipherBytes[0:len(cipherBytes)])

		plainBytes, _ = pkcs7.Pkcs7strip(plainBytes, aes.BlockSize)

		plainText = string(plainBytes)
	}

	if isCamellia256Used || isCamellia192Used || isCamellia128Used {
		block, cipherError := camellia.NewCipher(derivativeKey)
		if cipherError != nil {
			panic(cipherError)
		}

		plainBytes = make([]byte, len(cipherBytes))

		mode := cipher.NewCBCDecrypter(block, initializationVector)
		mode.CryptBlocks(plainBytes, cipherBytes[0:len(cipherBytes)])

		plainBytes, _ = pkcs7.Pkcs7strip(plainBytes, aes.BlockSize)

		plainText = string(plainBytes)
	}

	fmt.Printf("%s\n", plainText)
}

func keyLengthForAlgo(algo string) int {
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
