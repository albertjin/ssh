package ssh

import (
    "crypto"
    "crypto/cipher"
    "crypto/hmac"
    "crypto/rsa"
    "crypto/sha1"
    "errors"
    "math/big"
)

func (t *transport) dh(k *kexres, checkHostKey func([]byte)error) error {
    switch k.Kex {
    case "diffie-hellman-group1-sha1":
        return t.dhWith(k, checkHostKey, dh1_prime, dh1_gen)
    case "diffie-hellman-group14-sha1":
        return t.dhWith(k, checkHostKey, dh14_prime, dh14_gen)
    }
    return errors.New("Unknown kex method: " + k.Kex)
}

func (s *transport) dhWith(k *kexres, checkHostKey func([]byte) error, prime, gen *big.Int) error {
    // C: MsgKexdhInit
    X, E := dhGenKey(gen, prime)
    s.Packet().Byte(MsgKexdhInit).U32Bytes(bS(E)).Commit()

    // S: MsgKexdhReply
    packet := <-s.packets
    var code byte
    var H, K_S, Fs, signatureH []byte
    if !NewDecoder(packet).Byte(&code).U32Bytes(&K_S).U32Bytes(&Fs).U32Bytes(&signatureH).IsEnd() {
        return errors.New("packet has unparsed data")
    }

    if checkHostKey != nil {
        err := checkHostKey(K_S)
        if err != nil {
            return err
        }
    }

    F := pS(Fs)
    K := big.NewInt(0).Exp(F, X, prime)

    var skAlgo string
    skP := NewDecoder(K_S)
    skP.U32String(&skAlgo)

    firstTime := s.session_id == nil

    switch skAlgo {
    case "ssh-rsa":
        var rsaes, rsans []byte
        skP.U32Bytes(&rsaes).U32Bytes(&rsans)
        skPub := &rsa.PublicKey{pS(rsans), int(pS(rsaes).Int64())}
        H = hashSHA1(NewEncoder().U32String(ident).U32String(s.rident).U32Bytes(s.ckex).U32Bytes(s.skex).U32Bytes(K_S).U32Bytes(bS(E)).U32Bytes(Fs).U32Bytes(bS(K)).Out())
        if firstTime {
            s.session_id = H
        }
        var sigalgo string
        var sigdata []byte
        NewDecoder(signatureH).U32String(&sigalgo).U32Bytes(&sigdata).End()

        err := rsa.VerifyPKCS1v15(skPub, crypto.SHA1, hashSHA1(H), sigdata)
        if err != nil {
            return err
        }
    default:
        panic(skAlgo)
    }

    // C: MsgNewkeys
    s.Packet().Byte(MsgNewkeys).Commit()

    // S: MsgNewkeys
    packet = <-s.packets
    if len(packet) != 1 {
        return errors.New("packet has unparsed data")
    } else if code = packet[0]; code != MsgNewkeys {
        return errors.New("expected MsgNewkeys")
    }

    // initialize crypto
    hash := func(b byte) []byte {
        return hashSHA1(NewEncoder().U32Bytes(bS(K)).Bytes(H).Byte(b).Bytes(s.session_id).Out())
    }
    switch k.EncCS {
    case "aes128-cbc":
        s.wc = cipher.NewCBCEncrypter(newAES(hash('C')[0:16]), hash('A')[0:16])
    case "aes128-ctr":
        s.wc = newCTR(newAES(hash('C')[0:16]), hash('A')[0:16])
    case "aes256-ctr":
        s.wc = newCTR(newAES(hash('C')[0:32]), hash('A')[0:32])
    }
    switch k.EncSC {
    case "aes128-cbc":
        s.rc = cipher.NewCBCDecrypter(newAES(hash('D')[0:16]), hash('B')[0:16])
    case "aes128-ctr":
        s.rc = newCTR(newAES(hash('D')[0:16]), hash('B')[0:16])
    case "aes256-ctr":
        s.rc = newCTR(newAES(hash('D')[0:32]), hash('B')[0:32])
    }
    s.wh = hmac.New(sha1.New, hash('E'))
    s.rh = hmac.New(sha1.New, hash('F'))
    s.newkey<- 0

    return nil
}
