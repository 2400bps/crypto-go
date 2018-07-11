package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"math/big"
)

// RsaPublicKey for encrypting sensitive data that must be transported in
// public.
type RsaPublicKey struct {
	*rsa.PublicKey
}

// NewRsaPublicKey returns an RsaPublicKey from an existing public key. It
// does not verify that the public key was generated correctly.
func NewRsaPublicKey(publicKey *rsa.PublicKey) RsaPublicKey {
	return RsaPublicKey{
		PublicKey: publicKey,
	}
}

// NewRsaPublicKeyFromBytes decodes a slice of bytes into an RsaPublicKey. It
// assumes that the bytes slice is compliant with the Republic Protocol
// Keystore standard.
func NewRsaPublicKeyFromBytes(data []byte) (RsaPublicKey, error) {
	reader := bytes.NewReader(data)
	e := int64(0)
	if err := binary.Read(reader, binary.BigEndian, &e); err != nil {
		return RsaPublicKey{}, err
	}
	n := make([]byte, reader.Len())
	if err := binary.Read(reader, binary.BigEndian, n); err != nil {
		return RsaPublicKey{}, err
	}
	return RsaPublicKey{
		PublicKey: &rsa.PublicKey{
			E: int(e),
			N: big.NewInt(0).SetBytes(n),
		},
	}, nil
}

// Bytes returns a byte representation of the RsaPublicKey using the Republic
// Protocol Keystore standard for binary marshaling.
func (key *RsaPublicKey) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, int64(key.E)); err != nil {
		return []byte{}, err
	}
	if err := binary.Write(buf, binary.BigEndian, key.N.Bytes()); err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

// Encrypt a plain text message and return the cipher text.
func (key *RsaPublicKey) Encrypt(plainText []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, key.PublicKey, plainText, []byte{})
}

// RsaPrivateKey for decrypting sensitive data that must be transported in
// public.
type RsaPrivateKey struct {
	*rsa.PrivateKey
}

// NewRsaPrivateKey returns an RsaPrivateKey from an existing private key. It
// does not verify that the private key was generated correctly. It precomputes
// values for improved performance
func NewRsaPrivateKey(privateKey *rsa.PrivateKey) RsaPrivateKey {
	privateKey.Precompute()
	return RsaPrivateKey{
		PrivateKey: privateKey,
	}
}

// RandomRsaPrivateKey using 2048 bits, with precomputed values for improved
// performance.
func RandomRsaPrivateKey() (RsaPrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	privateKey.Precompute()
	if err != nil {
		return RsaPrivateKey{}, err
	}
	return RsaPrivateKey{
		PrivateKey: privateKey,
	}, nil
}

// Decrypt a cipher text and return the plain text message.
func (key *RsaPrivateKey) Decrypt(cipherText []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, key.PrivateKey, cipherText, []byte{})
}

// PublicKey returns the RsaPublicKey associated with this RsaPrivateKey.
func (key *RsaPrivateKey) PublicKey() *RsaPublicKey {
	publicKey := NewRsaPublicKey(&key.PrivateKey.PublicKey)
	return &publicKey
}

// Equal returns true if two RsaPrivateKeys are exactly equal.
func (key *RsaPrivateKey) Equal(rhs *RsaPrivateKey) bool {
	if len(key.Primes) != len(rhs.Primes) {
		return false
	}
	for i := range key.Primes {
		if key.Primes[i].Cmp(rhs.Primes[i]) != 0 {
			return false
		}
	}
	return key.D.Cmp(rhs.D) == 0 &&
		key.N.Cmp(rhs.N) == 0 &&
		key.E == rhs.E
}

// MarshalJSON implements the json.Marshaler interface. The RsaPrivateKey is
// formatted according to the Republic Protocol Keystore standard.
func (key RsaPrivateKey) MarshalJSON() ([]byte, error) {
	jsonKey := map[string]interface{}{}
	// Private key
	jsonKey["d"] = key.D.Bytes()
	jsonKey["primes"] = [][]byte{}
	for _, p := range key.Primes {
		jsonKey["primes"] = append(jsonKey["primes"].([][]byte), p.Bytes())
	}
	// Public key
	jsonKey["n"] = key.N.Bytes()
	jsonKey["e"] = key.E
	return json.Marshal(jsonKey)
}

// UnmarshalJSON implements the json.Unmarshaler interface. An RsaPrivateKey is
// created from data that is assumed to be compliant with the Republic Protocol
// Keystore standard. The RsaPrivateKey will be precomputed.
func (key *RsaPrivateKey) UnmarshalJSON(data []byte) error {
	jsonKey := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &jsonKey); err != nil {
		return err
	}

	var err error

	// Private key
	key.PrivateKey = new(rsa.PrivateKey)
	key.PrivateKey.D, err = unmarshalBigIntFromMap(jsonKey, "d")
	if err != nil {
		return err
	}
	key.PrivateKey.Primes, err = unmarshalBigIntsFromMap(jsonKey, "primes")
	if err != nil {
		return err
	}

	// Public key
	key.PrivateKey.PublicKey = rsa.PublicKey{}
	key.PrivateKey.PublicKey.N, err = unmarshalBigIntFromMap(jsonKey, "n")
	if err != nil {
		return err
	}
	key.PrivateKey.PublicKey.E, err = unmarshalIntFromMap(jsonKey, "e")
	if err != nil {
		return err
	}

	key.Precompute()
	return nil
}
