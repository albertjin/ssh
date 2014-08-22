package ssh

import (
	"crypto/aes"
	"crypto/cipher"
	r "crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"errors"
	"io"
	pr "math/rand"
	"strings"
)

func rand(n int) []byte {
	var buf = make([]byte, n)
	_, err := io.ReadFull(r.Reader, buf)
	if err != nil {
		panic(err)
	}
	return buf
}

func namelistCheck(client, server string) (string, bool, error) {
	cs := strings.Split(client, ",")
	ss := strings.Split(server, ",")
	guess := true
	for _, c := range cs {
		for _, s := range ss {
			if c == s {
				return c, guess, nil
			}
		}
		guess = false
	}
	return "", false, errors.New("No matching algorithm found")
}

var rng = pr.New(pr.NewSource(rand64()))

func rand64() int64 {
	return int64(bigendian.Uint64(rand(8)))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func newAES(bs []byte) cipher.Block {
	c, err := aes.NewCipher(bs)
	if err != nil {
		panic(err)
	}
	return c
}

func hashSHA1(raw []byte) []byte {
	hash := sha1.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

type ctr struct {
	cipher.Stream
	BS int
}

func (c ctr) BlockSize() int {
    return c.BS
}

func (c ctr) CryptBlocks(dst, src []byte) {
    c.Stream.XORKeyStream(dst, src)
}

func newCTR(c cipher.Block, iv []byte) ctr {
	return ctr{cipher.NewCTR(c, iv), c.BlockSize()}
}

type NullCrypto struct{
}

func (NullCrypto) BlockSize() int {
    return 16
}

func (NullCrypto) CryptBlocks(dst, src []byte) {
    copy(dst, src)
}

type NullHash struct{
}

func (NullHash) Write(b []byte) (int, error) {
    return len(b), nil
}

func (NullHash) Sum(b []byte) []byte {
    return []byte{}
}

func (NullHash) Reset() {
}

func (NullHash) Size() int {
    return 0
}

func (NullHash) BlockSize() int {
    return 0
}

func constEq(a, b []byte) bool {
	var equal = 1
	l := len(a)
	if l > len(b) {
		l = len(b)
	}
	for i := 0; i < l; i++ {
		equal &= subtle.ConstantTimeByteEq(a[i], b[i])
	}
	return l == len(a) && equal == 1
}

var Log = func(int, string, ...interface{}) {
}
