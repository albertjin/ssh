package ssh

import (
	"bitbucket.org/taruti/bigendian"
	"bufio"
	"bytes"
	"crypto/cipher"
	"hash"
	"io"
	"net"
	"os"
)

type ssh struct {
	c net.Conn
	r *bufio.Reader
	rc cipher.BlockMode
	wc cipher.BlockMode
	rh hash.Hash
	wh hash.Hash
	rseq, wseq uint32
	rident string
	ckex, skex []byte
	session_id []byte
}


func connect(host string) (*ssh,os.Error) {
	c,err := net.Dial("tcp", host+":22")
	if err!=nil {
		return nil,err
	}

	_,err = c.Write([]byte(ident+"\r\n"))
	if err!=nil {
		return nil,err
	}

	r := bufio.NewReader(c)

	var line []byte
	var prefix bool
	for {
		line, prefix, err = r.ReadLine()
		if err!=nil {
			return nil,err
		}
		if prefix {
			return nil,os.NewError("Too long identification line")
		}
		Log(1,"%s",line)
		if bytes.HasPrefix(line, []byte("SSH-2.0-")) {
			break 
		}
		if bytes.HasPrefix(line, []byte("SSH-")) {
			return nil,os.NewError("Unsupported ssh version")
		}
	}

	return &ssh{c, r, NullCrypto{}, NullCrypto{}, NullHash{}, NullHash{}, 0, 0, string(line), nil, nil, nil}, nil
}

func readPacket(c *ssh) ([]byte, os.Error) {
	l := c.rc.BlockSize()
	if l < 16 {
		l = 16
	}
	
	// read packet header
	b := make([]byte, l)
	_, err := io.ReadFull(c.r, b)
	if err!=nil {
		return nil,err
	}
	
	Log(9,"WIRE = %X",b)
	// decrypt header
	c.rc.CryptBlocks(b,b)
	Log(9,"DEC  = %X",b)

	lfield   := int(bigendian.U32(b))
	lpadding := int(b[4])
	// FIXME add checks here to validate packet
	lhash    := c.rh.Size()
	lrest    := 4 + lfield + lhash - len(b)

	if lrest > 12*1024*1024 || lfield<0 {
		Log(0, "lfield %d lrest %d", lfield, lrest)
		return nil, os.NewError("too large packet")
	}

	packet := make([]byte, len(b)+lrest)
	copy(packet, b)
	rest := packet[len(b):]
	_,err = io.ReadFull(c.r,rest)
	if err!=nil {
		return nil,err
	}
	c.rc.CryptBlocks(rest[0:lrest-lhash], rest[0:lrest-lhash])
	
	var rseqb [4]byte
	bigendian.PutU32(rseqb[:], c.rseq)
	c.rseq++

	c.rh.Reset()
	c.rh.Write(rseqb[:])
	c.rh.Write(packet[0:len(packet)-lhash])
	if !constEq(c.rh.Sum(), packet[len(packet)-lhash:]) {
		return nil,os.NewError("Invalid mac")
	}

	return packet[5:4+lfield-lpadding],nil
}

func writePacket(c *ssh, fun func(*bigendian.Printer)) {
	p := bigendian.NewPrinterWith(make([]byte, 5, 32))
	fun(p)
	b := p.Out()
	
	bs := c.wc.BlockSize()
	if bs < 16 {
		bs = 16
	}

	padding := bs - (len(b) % bs)
	if padding < 4 {
		padding += bs
	}

	b[4] = byte(padding)
	b = append(b, rand(padding)...)
	bigendian.PutU32(b, uint32(len(b)-4))

	var wseqb [4]byte
	bigendian.PutU32(wseqb[:], c.wseq)
	c.wseq++
	c.wh.Reset()
	c.wh.Write(wseqb[:])
	c.wh.Write(b)

	c.wc.CryptBlocks(b,b)

	b = append(b, c.wh.Sum()...)

	c.c.Write(b)
}

func writeKexInit(c *ssh) {
	p := bigendian.NewPrinter()
	p.Byte(msgKexInit).Bytes(rand(16))
	p.U32String(kexKex).U32String(kexShk)
	p.U32String(kexEnc).U32String(kexEnc)
	p.U32String(kexMac).U32String(kexMac)
	p.U32String(kexCom).U32String(kexCom)
	p.U32String(kexLan).U32String(kexLan)
	p.Byte(0).U32(0)
	c.ckex = p.Out()

	writePacket(c, func(p *bigendian.Printer) { p.Bytes(c.ckex) })
}

type kexres struct {
	Kex, Shk, EncCS, EncSC, MacCS, MacSC, ComCS, ComSC string
}

func parseKexInit(c *ssh, b []byte) (*kexres,os.Error) {
	var cookie []byte
	var kex, shk, ecs, esc, mcs, msc, ccs, csc, lcs, lsc string
	var follows byte
	var reserved uint32

	p := bigendian.NewParser(b).NBytes(16, &cookie)
	p.U32String(&kex).U32String(&shk)
	p.U32String(&ecs).U32String(&esc)
	p.U32String(&mcs).U32String(&msc)
	p.U32String(&ccs).U32String(&csc)
	p.U32String(&lcs).U32String(&lsc)
	p.Byte(&follows).U32(&reserved).End()

	guessed := true
	var r kexres
	var g bool
	var err os.Error

	r.Kex,g,err = namelistCheck(kexKex, kex)
	if err!=nil {
		return nil,err
	}
	guessed = g && guessed

	r.Shk,g,err = namelistCheck(kexShk, shk)
	if err!=nil {
		return nil,err
	}
	guessed = g && guessed

	r.EncCS,g,err = namelistCheck(kexEnc, ecs)
	if err!=nil {
		return nil,err
	}
	guessed = g && guessed
	r.EncSC,g,err = namelistCheck(kexEnc, esc)
	if err!=nil {
		return nil,err
	}
	guessed = g && guessed

	r.MacCS,g,err = namelistCheck(kexMac, mcs)
	if err!=nil {
		return nil,err
	}
	guessed = g && guessed
	r.MacSC,g,err = namelistCheck(kexMac, msc)
	if err!=nil {
		return nil,err
	}
	guessed = g && guessed

	r.ComCS,g,err = namelistCheck(kexCom, ccs)
	if err!=nil {
		return nil,err
	}
	guessed = g && guessed
	r.ComSC,g,err = namelistCheck(kexCom, csc)
	if err!=nil {
		return nil,err
	}
	guessed = g && guessed

	if guessed==false && follows>0 {
		readPacket(c)
	}

	return &r, nil
}

