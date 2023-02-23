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
	fs.StringVar(&enkaString, "string", "", "The 'enka' to parse and decrypt")
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

	if len(splittedEnkaString[3:]) != 5 {
		errorLog.Fatalln(fmt.Sprintf("Five sections are required; got %s", len(splittedEnkaString[2:])))
	}

	var encryptionKeyBytes = []byte(encryptionKey)
	var encryptionAlgorithm = splittedEnkaString[3]
	var keyDerivationFunction = splittedEnkaString[4]
	var encryptionKeySaltBytes, _ = base64.RawStdEncoding.DecodeString(strings.Replace(splittedEnkaString[5], "=", "", -1))
	var initalizationVector, _ = base64.RawStdEncoding.DecodeString(strings.Replace(splittedEnkaString[6], "=", "", -1))
	var cipherBytes, _ = base64.RawStdEncoding.DecodeString(strings.Replace(splittedEnkaString[7], "=", "", -1))

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
	var plainText string

	if isAes256CbcUsed {
		block, cipherError := aes.NewCipher(derivativeKey)
		if cipherError != nil {
			panic(cipherError)
		}

		plainBytes = make([]byte, len(cipherBytes))

		mode := cipher.NewCBCDecrypter(block, initalizationVector)
		mode.CryptBlocks(plainBytes, cipherBytes[0:len(cipherBytes)])

		plainBytes, _ = pkcs7.Pkcs7strip(plainBytes, aes.BlockSize)

		plainText = string(plainBytes)
	}

	fmt.Printf("%s\n", plainText)
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
