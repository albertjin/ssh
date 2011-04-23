package ssh

import (
	"bitbucket.org/taruti/bigendian"
	r "crypto/rand"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/subtle"
	pr "rand"
	"io"
	"os"
	"strings"
)

func rand(n int) []byte {
	var buf = make([]byte, n)
	_, err := io.ReadFull(r.Reader, buf)
	if err!=nil { panic(err) }
	return buf
}

func namelistCheck(client, server string) (string,bool,os.Error) {
	cs := strings.Split(client, ",", -1)
	ss := strings.Split(server, ",", -1)
	guess := true
	for _,c := range cs {
		for _,s := range ss {
			if c==s {
				return c,guess,nil
			}
		}
		guess = false
	}
	return "", false, os.NewError("No matching algorithm found")
} 

var rng = pr.New(pr.NewSource(crnd64()))

func crnd64() int64 {
	return int64(bigendian.U64(rand(8)))
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func newAES(bs []byte) *aes.Cipher {
	c,e := aes.NewCipher(bs)
	if e!=nil { panic(e) }
	return c
}

func sha1H(raw []byte) []byte {
	h := sha1.New()
	h.Write(raw)
	return h.Sum()
}

type ctr struct {
	cipher.Stream
	BS int
}
func (c ctr)BlockSize() int { return c.BS }
func (c ctr)CryptBlocks(dst,src []byte) { c.Stream.XORKeyStream(dst, src) }
func newCTR(c cipher.Block, iv []byte) ctr {
	return ctr{cipher.NewCTR(c,iv), c.BlockSize()}
}

type NullCrypto struct {}
func (NullCrypto)BlockSize() int { return 16 }
func (NullCrypto)CryptBlocks(dst, src []byte) { copy(dst, src) }

type NullHash struct {}
func (NullHash)Write(b []byte) (int,os.Error) { return len(b), nil }
func (NullHash)Sum() []byte { return []byte{} }
func (NullHash)Reset() {}
func (NullHash)Size() int { return 0 }

func constEq(a, b []byte) bool {
    var equal = 1
    l := len(a)
	if l > len(b) { l=len(b) }
	for i := 0; i<l; i++ {
		equal &= subtle.ConstantTimeByteEq(a[i],b[i])
	}
	return l==len(a) && equal==1
}

var Log = func(int,string,...interface{}) {}

