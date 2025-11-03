# enka
_Enkapsulate_ your data!

_enka_ is a CLI tool to encrypt strings to a common format, which can be decrypted by other applications.

## The problem
Encrypting data requires knowledge of certain parameters like the encryption algorithm, the KDF and so on.
OpenSSL does not include such information in its output, so I hacked something together.

## The solution
_enka_ gives you following result:

```
$ ./enka encrypt --algo aes256cbc --kdf pbkdf2:650000:sha256 --text kasnudelisbesseralswienerschnitzel --key obaehrlich
%enka%v1%aes256cbc%pbkdf2:650000:sha256%DH3Z4u0DeLk=%RoTCnO59r8pe2PeJDJoh1Q==%sWyo2KkRVk4PfgWAx/OeYb46SeDXwn/pUhOn2/6rAKXBr/w233cfavspr0GThMXP
$ 
```
This can be dissected into following parts:  
```
                program enka
                version v1
              algorithm aes256cbc
key derivation function pbkdf2:650000:sha256 (function : iteration count : hash function)
                   salt DH3Z4u0DeLk=
   intialization vector RoTCnO59r8pe2PeJDJoh1Q==
         encrypted text sWyo2KkRVk4PfgWAx/OeYb46SeDXwn/pUhOn2/6rAKXBr/w233cfavspr0GThMXP
```

With that information the text can be decrypted by other applications (like OpenSSL for example):
```
$ echo $(echo -n "sWyo2KkRVk4PfgWAx/OeYb46SeDXwn/pUhOn2/6rAKXBr/w233cfavspr0GThMXP" | openssl enc -d -base64 -A -aes-256-cbc -pbkdf2 -iter 650000 -md sha256 -S 0c7dd9e2ed0378b9 -iv 4684c29cee7dafca5ed8f7890c9a21d5 -pass pass:obaehrlich)
kasnudelisbesseralswienerschnitzel
$ 
```

But you can use the _enka_ tool for that too:
```
$ echo $(./enka decrypt --string %enka%v1%aes256cbc%pbkdf2:650000:sha256%DH3Z4u0DeLk=%RoTCnO59r8pe2PeJDJoh1Q==%sWyo2KkRVk4PfgWAx/OeYb46SeDXwn/pUhOn2/6rAKXBr/w233cfavspr0GThMXP --key obaehrlich)
kasnudelisbesseralswienerschnitzel
$ 
```
