package main

import (
	"fmt"
	"github.com/IQooLogic/obfuscator"
)

func main() {
	originalText := "simple text or password"
	o := obfuscator.New([]byte("randompassphrase"),
		obfuscator.WithSaltLength(6),
		obfuscator.WithSeparator(obfuscator.DefaultSeparator))
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
