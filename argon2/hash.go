package argon2

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strconv"
	"strings"
)

type Argon2HashParams struct {
	Memory  uint32 `argon2:"m"`
	Time    uint32 `argon2:"t"`
	Threads uint8  `argon2:"p"`
}

type Argon2Hash struct {
	Type       string
	Version    uint64 `argon2:"v"`
	Params     Argon2HashParams
	Hash, Salt []byte
}

var (
	ErrInvalidArgon2Hash   = errors.New("invalid argon2 hash")
	ErrInvalidArgon2Params = errors.New("invalid argon2 params")
)

func marshalArgon2Params(v any) ([]byte, error) {
	var b strings.Builder
	s := reflect.ValueOf(v).Elem()

	for i := range s.NumField() {
		fieldType := s.Type().Field(i)
		fieldValue := s.Field(i)

		if fieldValue.CanUint() {
			if name := fieldType.Tag.Get("argon2"); name != "" {
				b.WriteRune(',')
				b.WriteString(name)
				b.WriteByte('=')
				b.WriteString(strconv.FormatUint(fieldValue.Uint(), 10))
			}
		}
	}

	return []byte(b.String()[1:]), nil
}

func unmarshalArgon2Params(input string, v any) error {
	values := map[string]reflect.Value{}
	s := reflect.ValueOf(v).Elem()

	for i := range s.NumField() {
		fieldType := s.Type().Field(i)
		fieldValue := s.Field(i)

		if name := fieldType.Tag.Get("argon2"); name != "" {
			values[name] = fieldValue
		}
	}

	var found bool

	for {
		var v string
		v, input, found = strings.Cut(input, ",")
		key, value, valid := strings.Cut(v, "=")

		if !valid {
			return ErrInvalidArgon2Params
		}

		if valuePtr, exists := values[key]; exists {
			valueInt, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return err
			}

			if valuePtr.CanSet() {
				valuePtr.SetUint(valueInt)
			}
		}

		if !found {
			return nil
		}
	}
}

func ParseEncodedTextHash(hash string) (*Argon2Hash, error) {
	fields := strings.Split(hash, "$")
	if len(fields) != 6 {
		return nil, ErrInvalidArgon2Hash
	}

	result := Argon2Hash{
		Type: fields[1],
	}

	if err := unmarshalArgon2Params(fields[2], &result); err != nil {
		return nil, err
	}

	if err := unmarshalArgon2Params(fields[3], &result.Params); err != nil {
		return nil, err
	}

	rawHash, err := base64.RawStdEncoding.DecodeString(fields[5])
	if err != nil {
		return nil, err
	}
	result.Hash = rawHash

	rawSalt, err := base64.RawStdEncoding.DecodeString(fields[4])
	if err != nil {
		return nil, err
	}
	result.Salt = rawSalt

	return &result, nil
}

func (hash Argon2Hash) String() string {
	var b strings.Builder
	b.WriteRune('$')
	b.WriteString(hash.Type)
	b.WriteRune('$')

	v, _ := marshalArgon2Params(&hash)
	b.Write(v)

	b.WriteRune('$')

	v, _ = marshalArgon2Params(&hash.Params)
	b.Write(v)

	b.WriteRune('$')
	b.WriteString(base64.RawStdEncoding.EncodeToString(hash.Salt))
	b.WriteRune('$')
	b.WriteString(base64.RawStdEncoding.EncodeToString(hash.Hash))

	return b.String()
}
