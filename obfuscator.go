package obfuscator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const SaltLength = 8
const DefaultSeparator = "$"
const Version = "o1"

var ErrorInvalidObfuscatedString = errors.New("invalid obfuscated string")
var ErrorUnsupportedVersion = errors.New("unsupported obfuscator version")

type Config struct {
	passphrase []byte
	saltLength uint8
	separator  string
}

type Option func(*Config)

type Obfuscator struct {
	config *Config
}

func New(passphrase []byte, options ...Option) Obfuscator {
	if passphrase == nil {
		panic("passphrase must not be nil")
	}

	config := &Config{
		passphrase: passphrase,
		saltLength: SaltLength,
		separator:  DefaultSeparator,
	}

	for _, o := range options {
		o(config)
	}

	return Obfuscator{config: config}
}

func WithSaltLength(length uint8) Option {
	if length == 0 {
		panic("salt length must not be 0")
	}
	return func(s *Config) {
		s.saltLength = length
	}
}

func WithSeparator(separator string) Option {
	return func(s *Config) {
		s.separator = separator
	}
}

func (o Obfuscator) Obfuscate(text string) (string, error) {
	salt, err := o.generateSalt(o.config.saltLength)
	if err != nil {
		return "", err
	}
	key := o.deriveKey(o.config.passphrase, salt)
	iv := o.genCryptoKey()
	cipherText, err := o.encrypt(text, key, iv)
	if err != nil {
		return "", err
	}
	encodedSalt := base64.StdEncoding.EncodeToString(salt)
	encodedIv := base64.StdEncoding.EncodeToString(iv)
	encodedCipherText := base64.StdEncoding.EncodeToString(cipherText)
	return fmt.Sprintf("%s%s%s%s%s%s%s%s", o.config.separator, Version,
		o.config.separator, encodedSalt, o.config.separator, encodedIv,
		o.config.separator, encodedCipherText), nil
}

func (o Obfuscator) encrypt(text string, key, iv []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nil, iv, []byte(text), nil), nil
}

func (o Obfuscator) Unobfuscate(obfusctatedText string) (string, error) {
	parts := strings.Split(obfusctatedText, o.config.separator)
	if len(parts) > 1 {
		parts = parts[1:] // remove first element, it is space
	}
	if len(parts) != 4 {
		return "", ErrorInvalidObfuscatedString
	}

	version := parts[0]
	switch version {
	case "o1":
		unobfuscatedBytes, err := o.decrypt(parts)
		if err != nil {
			return "", err
		}
		return string(unobfuscatedBytes), nil
	default:
		return "", ErrorUnsupportedVersion
	}
}

func (o Obfuscator) decrypt(parts []string) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	iv, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	cipherText, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, err
	}
	key := o.deriveKey(o.config.passphrase, salt)

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	obfuscatedBytes, err := gcm.Open(nil, iv, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return obfuscatedBytes, nil
}

func (o Obfuscator) generateSalt(length uint8) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	return salt, err
}

func (Obfuscator) deriveKey(passphrase, salt []byte) []byte {
	return pbkdf2.Key(passphrase, salt, 1000, 32, sha256.New)
}

func (Obfuscator) genCryptoKey() []byte {
	iv := make([]byte, 12)
	_, _ = rand.Read(iv)
	return iv
}
