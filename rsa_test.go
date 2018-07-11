package crypto_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/republicprotocol/crypto-go"
)

var _ = Describe("Rsa keys", func() {

	Context("when generating", func() {

		It("should be able to generate a random RsaPrivateKey without returning an error", func() {
			_, err := RandomRsaPrivateKey()
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should equal itself", func() {
			key, err := RandomRsaPrivateKey()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(key.Equal(&key)).Should(BeTrue())
		})

		It("should not equal another randomly generated RsaPrivateKey", func() {
			key1, err := RandomRsaPrivateKey()
			Expect(err).ShouldNot(HaveOccurred())
			key2, err := RandomRsaPrivateKey()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(key1.Equal(&key2)).Should(BeFalse())
		})
	})

	Context("when encrypting and decrypting", func() {

		It("should be able to encrypt a plain text message", func() {
			key, err := RandomRsaPrivateKey()
			Expect(err).ShouldNot(HaveOccurred())

			plainText := []byte("REN")
			_, err = key.PublicKey().Encrypt(plainText)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should be able to decrypt an encrypted cipher text", func() {
			key, err := RandomRsaPrivateKey()
			Expect(err).ShouldNot(HaveOccurred())

			plainText := []byte("REN")
			cipherText, err := key.PublicKey().Encrypt(plainText)
			Expect(err).ShouldNot(HaveOccurred())
			plainTextDecrypted, err := key.Decrypt(cipherText)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(plainText).Should(Equal(plainTextDecrypted))
		})

	})

	Context("when marshaling and unmarshaling", func() {

		It("should be able to marshal and unmarshal as JSON", func() {
			key, err := RandomRsaPrivateKey()
			Expect(err).ShouldNot(HaveOccurred())

			data, err := key.MarshalJSON()
			Expect(err).ShouldNot(HaveOccurred())

			keyDecoded := RsaPrivateKey{}
			err = keyDecoded.UnmarshalJSON(data)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(key.Equal(&keyDecoded)).Should(BeTrue())
		})

		It("should be able to marshal and unmarshal public keys as bytes", func() {
			key, err := RandomRsaPrivateKey()
			Expect(err).ShouldNot(HaveOccurred())

			data, err := key.PublicKey().Bytes()
			Expect(err).ShouldNot(HaveOccurred())

			publicKey, err := NewRsaPublicKeyFromBytes(data)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(key.N).Should(Equal(publicKey.N))
			Expect(key.E).Should(Equal(publicKey.E))
		})

	})
})
