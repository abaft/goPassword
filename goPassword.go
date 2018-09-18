package goPassword

import (
	"bytes"
	"crypto/rand"
	b64 "encoding/base64"
	"errors"
	"golang.org/x/crypto/argon2"
	"io"
	"strconv"
	"strings"
)

const (
	time     = 1
	memory   = 64 * 1024
	threads  = 4
	keyLen   = 32
	saltSize = 32
)

type hashed struct {
	hash    []byte
	salt    []byte
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

func HashPassword(plaintextPassword string) string {
	hash := new(hashed)
	hash.init()
	hash.hash = hash.hashString(plaintextPassword)
	return hash.encode()
}

func PasswordCheck(plaintextPassword, encHash string) bool {
	hash, err := decode(encHash)
	if err != nil {
		return false
	}
	test := hash.hashString(plaintextPassword)
	return bytes.Compare(test, hash.hash) == 0
}

func (h *hashed) init() {
	rawSalt := make([]byte, saltSize)
	_, err := io.ReadFull(rand.Reader, rawSalt)
	if err != nil {
		return
	}

	h.salt = rawSalt
	h.time = time
	h.memory = memory
	h.threads = threads
	h.keyLen = keyLen
}

func (h *hashed) hashString(plaintextPassword string) []byte {
	return argon2.Key([]byte(plaintextPassword), h.salt, h.time, h.memory, h.threads, h.keyLen)
}

func (h *hashed) encode() string {
	var rtnBuffer bytes.Buffer

	rtnBuffer.WriteString("$argon2$")
	rtnBuffer.WriteString(b64.StdEncoding.EncodeToString(h.hash) + "$")
	rtnBuffer.WriteString(b64.StdEncoding.EncodeToString(h.salt) + "$")
	rtnBuffer.WriteString(strconv.FormatUint(uint64(h.time), 16) + "$")
	rtnBuffer.WriteString(strconv.FormatUint(uint64(h.memory), 16) + "$")
	rtnBuffer.WriteString(strconv.FormatUint(uint64(h.threads), 16) + "$")
	rtnBuffer.WriteString(strconv.FormatUint(uint64(h.keyLen), 16))

	return rtnBuffer.String()
}

func decode(enc string) (*hashed, error) {
	elements := strings.Split(enc, "$")
	if len(elements) != 8 {
		return nil, errors.New("Incorrect String")
	}
	if elements[1] != "argon2" {
		return nil, errors.New("Not argon2")
	}

	hash, _ := b64.StdEncoding.DecodeString(elements[2])
	salt, _ := b64.StdEncoding.DecodeString(elements[3])
	time, _ := strconv.ParseUint(elements[4], 16, 32)
	memory, _ := strconv.ParseUint(elements[5], 16, 32)
	threads, _ := strconv.ParseUint(elements[6], 16, 8)
	keyLen, _ := strconv.ParseUint(elements[7], 16, 32)

	h := new(hashed)
	*h = hashed{
		hash:    hash,
		salt:    salt,
		time:    uint32(time),
		memory:  uint32(memory),
		threads: uint8(threads),
		keyLen:  uint32(keyLen),
	}

	return h, nil
}
