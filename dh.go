package ssh

import (
	"crypto"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"math/big"
)

func (c *ssh) dh(k *kexres, C *C) error {
	switch k.Kex {
	case "diffie-hellman-group1-sha1":
		return c.dhWith(k, C, dh1_prime, dh1_gen)
	case "diffie-hellman-group14-sha1":
		return c.dhWith(k, C, dh14_prime, dh14_gen)
	}
	panic("Unknown kex method: " + k.Kex)
}

func (c *ssh) dhWith(k *kexres, C *C, prime, gen *big.Int) error {
	X, E := dhGenKey(gen, prime)
	c.writePacket(func(p *Printer) {
		p.Byte(msgKexdhInit).U32Bytes(bS(E))
	})

	b, e := c.readPacket()
	if e != nil {
		return e
	}
	var code byte
	var H, K_S, Fs, sigh []byte

	NewParser(b).Byte(&code).U32Bytes(&K_S).U32Bytes(&Fs).U32Bytes(&sigh).End()

	err := C.HostKeyFun(K_S)
	if err != nil {
		return err
	}

	F := pS(Fs)
	K := big.NewInt(0).Exp(F, X, prime)
	skP := NewParser(K_S)
	var skAlgo string
	skP.U32String(&skAlgo)
	switch skAlgo {
	case "ssh-rsa":
		var rsaes, rsans []byte
		skP.U32Bytes(&rsaes).U32Bytes(&rsans)
		skPub := &rsa.PublicKey{pS(rsans), int(pS(rsaes).Int64())}
		H = c.calculateH(K_S, bS(E), Fs, bS(K))
		if c.session_id == nil {
			c.session_id = H
		}
		var sigalgo string
		var sigdata []byte
		NewParser(sigh).U32String(&sigalgo).U32Bytes(&sigdata).End()

		err := rsa.VerifyPKCS1v15(skPub, crypto.SHA1, sha1H(H), sigdata)
		if err != nil {
			return err
		}
	default:
		panic(skAlgo)
	}
	c.writePacket(func(p *Printer) { p.Byte(msgNewkeys) })
	b, e = c.readPacket()
	NewParser(b).Byte(&code).End()
	if e != nil || code != msgNewkeys {
		panic("Expected msgNewkeys")
	}
	hash := func(b byte) []byte {
		return sha1H(NewPrinter().U32Bytes(bS(K)).Bytes(H).Byte(b).Bytes(c.session_id).Out())
	}
	switch k.EncCS {
	case "aes128-cbc":
		c.wc = cipher.NewCBCEncrypter(newAES(hash('C')[0:16]), hash('A')[0:16])
	case "aes128-ctr":
		c.wc = newCTR(newAES(hash('C')[0:16]), hash('A')[0:16])
	}
	switch k.EncSC {
	case "aes128-cbc":
		c.rc = cipher.NewCBCDecrypter(newAES(hash('D')[0:16]), hash('B')[0:16])
	case "aes128-ctr":
		c.rc = newCTR(newAES(hash('D')[0:16]), hash('B')[0:16])
	}
	c.wh = hmac.New(sha1.New, hash('E'))
	c.rh = hmac.New(sha1.New, hash('F'))
	return nil
}

func (c *ssh) calculateH(K_S, Es, Fs, Ks []byte) []byte {
	shkp := NewPrinter()
	shkp.U32String(ident).U32String(c.rident).U32Bytes(c.ckex).U32Bytes(c.skex)
	shkp.U32Bytes(K_S).U32Bytes(Es).U32Bytes(Fs).U32Bytes(Ks)
	return sha1H(shkp.Out())
}
