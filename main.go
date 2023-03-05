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
	"flag"
	"fmt"
	"log"
	"os"
)

var commands = map[string]func([]string, *log.Logger, *log.Logger){
	"encrypt": enka_encryption.Encrypt,
	"decrypt": enka_decryption.Decrypt,
}

var help bool
var errorLog = log.New(os.Stderr, "[enka] ", 0)
var outLog = log.New(os.Stdout, "[enka] ", 0)

func main() {
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

	command(flag.Args()[1:], outLog, errorLog)
}

func globalUsage(executable string) {
	fmt.Printf("Usage: %s [ --help ] encrypt [ --algo ] [ --kdf ] < --key > [ --salt ] < --text > [ --verbose ] | decrypt < --key > < --string >\n", executable)
}

func globalHelp() {
	fmt.Println("Help:")
	fmt.Println("  encrypt      The encryption module")
	fmt.Println("  decrypt      The decryption module")
}
