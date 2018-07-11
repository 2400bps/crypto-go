package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// An EcdsaPrivateKey is used for signing data and representing verifiable
// identities.
type EcdsaPrivateKey struct {
	*ecdsa.PrivateKey
}

// NewEcdsaPrivateKey returns an EcdsaPrivateKey from an existing private key.
// It does not verify that the private key was generated correctly.
func NewEcdsaPrivateKey(privateKey *ecdsa.PrivateKey) EcdsaPrivateKey {
	return EcdsaPrivateKey{
		PrivateKey: privateKey,
	}
}

// RandomEcdsaPrivateKey using a secp256k1 s256 curve.
func RandomEcdsaPrivateKey() (EcdsaPrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return EcdsaPrivateKey{}, err
	}
	return EcdsaPrivateKey{
		PrivateKey: privateKey,
	}, nil
}

// Sign implements the Signer interface. It uses the ecdsa.PrivateKey to sign
// the data without performing any kind of preprocessing of the data. If the
// data is not exactly 32 bytes, an error is returned.
func (key *EcdsaPrivateKey) Sign(data []byte) ([]byte, error) {
	return crypto.Sign(data, key.PrivateKey)
}

// Verify implements the Verifier interface. It uses its own address as the
// expected signatory.
func (key *EcdsaPrivateKey) Verify(data []byte, signature []byte) error {
	return NewEcdsaVerifier(key.PublicKey).Verify(data, signature)
}

// Equal returns true if two EcdsaPrivateKeys are exactly equal. The name of
// the elliptic.Curve is not checked.
func (key *EcdsaPrivateKey) Equal(rhs *EcdsaPrivateKey) bool {
	return key.D.Cmp(rhs.D) == 0 &&
		key.X.Cmp(rhs.X) == 0 &&
		key.Y.Cmp(rhs.Y) == 0 &&
		key.Curve.Params().P.Cmp(rhs.Curve.Params().P) == 0 &&
		key.Curve.Params().N.Cmp(rhs.Curve.Params().N) == 0 &&
		key.Curve.Params().B.Cmp(rhs.Curve.Params().B) == 0 &&
		key.Curve.Params().Gx.Cmp(rhs.Curve.Params().Gx) == 0 &&
		key.Curve.Params().Gy.Cmp(rhs.Curve.Params().Gy) == 0 &&
		key.Curve.Params().BitSize == rhs.Curve.Params().BitSize
}

// MarshalJSON implements the json.Marshaler interface. The EcdsaPrivateKey is
// formatted according to the Republic Protocol Keystore specification.
func (key EcdsaPrivateKey) MarshalJSON() ([]byte, error) {
	jsonKey := map[string]interface{}{}
	// Private key
	jsonKey["d"] = key.D.Bytes()

	// Public key
	jsonKey["x"] = key.X.Bytes()
	jsonKey["y"] = key.Y.Bytes()

	// Curve
	jsonKey["curveParams"] = map[string]interface{}{
		"p":    secp256k1.S256().P.Bytes(),  // the order of the underlying field
		"n":    secp256k1.S256().N.Bytes(),  // the order of the base point
		"b":    secp256k1.S256().B.Bytes(),  // the constant of the curve equation
		"x":    secp256k1.S256().Gx.Bytes(), // (x,y) of the base point
		"y":    secp256k1.S256().Gy.Bytes(),
		"bits": secp256k1.S256().BitSize, // the size of the underlying field
		"name": "s256",                   // the canonical name of the curve
	}
	return json.Marshal(jsonKey)
}

// UnmarshalJSON implements the json.Unmarshaler interface. An EcdsaPrivateKey
// is created from data that is assumed to be compliant with the Republic
// Protocol standard. The use of secp256k1 s256 curve is not checked.
func (key *EcdsaPrivateKey) UnmarshalJSON(data []byte) error {
	jsonKey := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &jsonKey); err != nil {
		return err
	}

	var err error

	// Private key
	key.PrivateKey = new(ecdsa.PrivateKey)
	key.PrivateKey.D, err = unmarshalBigIntFromMap(jsonKey, "d")
	if err != nil {
		return err
	}

	// Public key
	key.PrivateKey.PublicKey = ecdsa.PublicKey{}
	key.PrivateKey.PublicKey.X, err = unmarshalBigIntFromMap(jsonKey, "x")
	if err != nil {
		return err
	}
	key.PrivateKey.PublicKey.Y, err = unmarshalBigIntFromMap(jsonKey, "y")
	if err != nil {
		return err
	}

	// Curve
	if jsonVal, ok := jsonKey["curveParams"]; ok {
		curveParams := elliptic.CurveParams{}
		jsonCurveParams := map[string]json.RawMessage{}
		if err := json.Unmarshal(jsonVal, &jsonCurveParams); err != nil {
			return err
		}
		curveParams.P, err = unmarshalBigIntFromMap(jsonCurveParams, "p")
		if err != nil {
			return err
		}
		curveParams.N, err = unmarshalBigIntFromMap(jsonCurveParams, "n")
		if err != nil {
			return err
		}
		curveParams.B, err = unmarshalBigIntFromMap(jsonCurveParams, "b")
		if err != nil {
			return err
		}
		curveParams.Gx, err = unmarshalBigIntFromMap(jsonCurveParams, "x")
		if err != nil {
			return err
		}
		curveParams.Gy, err = unmarshalBigIntFromMap(jsonCurveParams, "y")
		if err != nil {
			return err
		}
		curveParams.BitSize, err = unmarshalIntFromMap(jsonCurveParams, "bits")
		if err != nil {
			return err
		}
		curveParams.Name, err = unmarshalStringFromMap(jsonCurveParams, "name")
		if err != nil {
			return err
		}
		key.PrivateKey.Curve = &curveParams
	} else {
		return fmt.Errorf("curveParams is nil")
	}
	return nil
}

// EcdsaVerifier is used to verify signatures produced by an EcdsaPrivateKey.
type EcdsaVerifier struct {
	ecdsa.PublicKey
}

// NewEcdsaVerifier returns an EcdsaVerifier that expects the signatory of all
// signatures that it checks to equal the given address.
func NewEcdsaVerifier(publicKey ecdsa.PublicKey) EcdsaVerifier {
	return EcdsaVerifier{
		PublicKey: publicKey,
	}
}

// Verify implements the Verifier interface.
func (verifier EcdsaVerifier) Verify(data []byte, signature []byte) error {
	if data == nil || len(data) == 0 {
		return ErrNilData
	}
	if signature == nil || len(signature) == 0 {
		return ErrNilSignature
	}
	publicKey, err := RecoverPublicKey(data, signature)
	if err != nil {
		return err
	}
	if verifier.PublicKey.Curve != publicKey.Curve {
		return ErrMalformedSignature
	}
	if verifier.PublicKey.X.Cmp(publicKey.X) != 0 {
		return ErrMalformedSignature
	}
	if verifier.PublicKey.Y.Cmp(publicKey.Y) != 0 {
		return ErrMalformedSignature
	}
	return nil
}

// RecoverPublicKey used to produce a signature.
func RecoverPublicKey(data []byte, signature []byte) (ecdsa.PublicKey, error) {

	// Returns 65-byte uncompress pubkey (0x04 | X | Y)
	publicKey, err := crypto.Ecrecover(data, signature)
	if err != nil {
		return ecdsa.PublicKey{}, err
	}

	// Rebuild the public key
	return ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     big.NewInt(0).SetBytes(publicKey[1:33]),
		Y:     big.NewInt(0).SetBytes(publicKey[33:65]),
	}, nil
}
