package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
)

var commands = map[string]func([]string){
	"encrypt": encrypt,
}

var verbose bool
var help bool
var errorLog = log.New(os.Stderr, "[enka] ", 0)
var outLog = log.New(os.Stdout, "[enka] ", 0)

func main() {
	flag.BoolVar(&verbose, "verbose", false, "Verbosity level")
	flag.BoolVar(&help, "help", false, "Show the global help")
	flag.Parse()

	if len(flag.Args()) == 0 {
		globalUsage(os.Args[0])
		globalHelp()
		os.Exit(1)
	}

	command, ok := commands[flag.Args()[0]]
	if !ok {
		globalUsage(os.Args[0])
		os.Exit(1)
	}

	if verbose {
		outLog.Println("Verbosity on")
	}

	command(flag.Args()[1:])
}

func globalUsage(executable string) {
	fmt.Printf("Usage: %s [ --verbose ] encrypt [ --algo ] [ --kdf ] [ --key ] [ --salt ] [ --text ]\n", executable)
}

func globalHelp() {
	fmt.Println("Help:")
	fmt.Println("  encrypt      The encryption module")
}

func encrypt(args []string) {
	var encryptionAlgorithm string
	var keyDerivationFunction string
	var encryptionKeySalt string
	var encryptionKey string
	var plainText string

	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	fs.StringVar(&encryptionAlgorithm, "algo", "aes256cbc", "The encryption algorithm to use")
	fs.StringVar(&keyDerivationFunction, "kdf", "pbkdf2:650000:sha256", "The KDF to use")
	fs.StringVar(&encryptionKey, "key", "", "The encryption key")
	fs.StringVar(&encryptionKeySalt, "salt", "", "A salt for the KDF")
	fs.StringVar(&plainText, "text", "", "The string to encrypt")
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
		plainBytes, _ = pkcs7pad(plainBytes, aes.BlockSize)

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

	// echo $(echo "abcd" | openssl enc -aes-256-cbc -k 1234 -pbkdf2 -e -base64 -A -S 0000000000000000 -iter 4096 -md sha1 -p -iv 00000000000000000000000000000000)
	// echo $(echo "a48yuBSSLSIXLKtxO0eAj5mujzIpgG4TcKc21Qtnwws=" | openssl enc -aes-256-cbc -k 1234 -pbkdf2 -d -base64 -A -salt -iter 4096 )
	// go build; echo $(./enka -key 1234 -text abcd)
	//echo $(echo "00000000000000000000000000000000" | openssl enc -aes-256-cbc -K 0000000000000000000000000000000000000000000000000000000000000000 -pbkdf2 -e -base64 -A -S 00000000 -iter 4096 -md sha1 -p -iv 00000000000000000000000000000000)
}

// pkcs7strip remove pkcs7 padding
func pkcs7strip(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7: Data is empty")
	}
	if length%blockSize != 0 {
		return nil, errors.New("pkcs7: Data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		return nil, errors.New("pkcs7: Invalid padding")
	}
	return data[:length-padLen], nil
}

// pkcs7pad add pkcs7 padding
func pkcs7pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 1 || blockSize >= 256 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	} else {
		padLen := blockSize - len(data)%blockSize
		padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
		return append(data, padding...), nil
	}
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
