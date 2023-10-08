# Welcome to IQooLogic/obfuscator

Introduction
------------
The obfuscator package enables Go programs to encode and decode sensitive values such as passwords to store them in config files.

Installation and usage
----------------------

The import path for the package is *github.com/IQooLogic/obfuscator*.

To install it, run:

    go get github.com/IQooLogic/obfuscator

License
-------

The obfuscator package is licensed under the MIT license.
Please see the LICENSE file for details.

See [`LICENSE`](./LICENSE)

Example
-------

```Go
package main

import (
	"fmt"
	"github.com/IQooLogic/obfuscator"
)

func main() {
	originalText := "simple text or password"
	o := obfuscator.New([]byte("randompassphrase"))
	// obfuscate
	obfuscatedText, err := o.Obfuscate(originalText)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	fmt.Printf("Obfuscated text: %s\n", obfuscatedText)

	// unobfuscate
	unobfuscatedText, err := o.Unobfuscate(obfuscatedText)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	fmt.Printf("Unobfuscated text: %s\n", unobfuscatedText)
}
```

See [`Examples`](./examples)