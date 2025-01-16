package pwdhash

type PasswordHasher interface {
	Hash(input []byte) (hash []byte, err error)
	Compare(input []byte, hash []byte) (matches bool)
}
