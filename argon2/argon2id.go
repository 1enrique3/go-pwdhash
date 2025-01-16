package argon2

import (
	"bytes"
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

type Argon2IDAlgorithm struct {
	HashParams Argon2HashParams

	// How many bytes long should be the raw hash output
	KeyLength uint32

	// How many bytes long should be the randomly generated salt
	SaltLength uint32
}

var Default = Argon2IDAlgorithm{
	HashParams: Argon2HashParams{
		Time:    10,
		Memory:  4 * 1024,
		Threads: 4,
	},
	KeyLength:  32,
	SaltLength: 16,
}

func (a Argon2IDAlgorithm) Hash(input []byte) ([]byte, error) {
	hash := Argon2Hash{
		Type:   "argon2id",
		Params: a.HashParams,
		Salt:   make([]byte, a.SaltLength),
	}

	if _, err := rand.Read(hash.Salt); err != nil {
		return nil, err
	}

	hash.Hash = argon2.IDKey(
		input,
		hash.Salt,
		hash.Params.Time,
		hash.Params.Memory,
		hash.Params.Threads,
		a.KeyLength,
	)

	return []byte(hash.String()), nil
}

func (a Argon2IDAlgorithm) Compare(input []byte, rawHash []byte) bool {
	hash, err := ParseEncodedTextHash(string(rawHash))
	if err != nil {
		return false
	}

	return bytes.Equal(
		argon2.IDKey(input, hash.Salt, hash.Params.Time, hash.Params.Memory, hash.Params.Threads, uint32(len(hash.Hash))),
		hash.Hash,
	)
}
