package ssh

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"errors"
	"hash"
	"io"
)

type transport struct {
	conn io.ReadWriteCloser
	in *bufio.Reader

	rc, wc cipher.BlockMode
	rh, wh hash.Hash
	rseq, wseq uint32

	packets chan []byte
	newkey chan int
	rident string

	ckex, skex, session_id []byte
}

func newTransport(conn io.ReadWriteCloser) (*transport, error) {
	_, err := conn.Write([]byte(ident + "\r\n"))
	if err != nil {
		return nil, err
	}

	in := bufio.NewReader(conn)

	var line []byte
	var prefix bool
	for {
		line, prefix, err = in.ReadLine()
		if err != nil {
			return nil, err
		}
		if prefix {
			return nil, errors.New("Too long identification line")
		}
		Log(1, "%s", line)
		if bytes.HasPrefix(line, []byte("SSH-2.0-")) {
			break
		}
		if bytes.HasPrefix(line, []byte("SSH-")) {
			return nil, errors.New("Unsupported ssh version")
		}
	}

	return &transport{conn, in, NullCrypto{}, NullCrypto{}, NullHash{}, NullHash{}, 0, 0, make(chan []byte, 512*1024), make(chan int, 1), string(line), nil, nil, nil}, nil
}

func (s *transport) readPacket() ([]byte, error) {
	bs := s.rc.BlockSize()
	if bs < 16 {
		bs = 16
	}

	// read packet header
	b := make([]byte, bs)
	_, err := io.ReadFull(s.in, b)
	if err != nil {
		return nil, err
	}

	Log(9, "WIRE = %X", b)
	// decrypt header
	s.rc.CryptBlocks(b, b)
	Log(9, "DEC  = %X", b)

	lfield := int(bigendian.Uint32(b))
	lpadding := int(b[4])
	// FIXME add checks here to validate packet
	lhash := s.rh.Size()
	lrest := 4 + lfield + lhash - len(b)

	if (lrest > 12*1024*1024) || (lfield < 0) {
		Log(0, "lfield %d lrest %d", lfield, lrest)
		return nil, errors.New("too large packet")
	}

	packet := make([]byte, len(b)+lrest)
	copy(packet, b)
	rest := packet[len(b):]
	_, err = io.ReadFull(s.in, rest)
	if err != nil {
		return nil, err
	}
	s.rc.CryptBlocks(rest[0:lrest-lhash], rest[0:lrest-lhash])

	var rseqb [4]byte
	bigendian.PutUint32(rseqb[:], s.rseq)
	s.rseq++

	s.rh.Reset()
	s.rh.Write(rseqb[:])
	s.rh.Write(packet[0 : len(packet)-lhash])
	if !constEq(s.rh.Sum(nil), packet[len(packet)-lhash:]) {
		return nil, errors.New("Invalid mac")
	}

	return packet[5 : 4+lfield-lpadding], nil
}

func (s *transport) Packet() *Encoder {
    return s.PacketN(0)
}

func (s *transport) PacketN(n int) *Encoder {
    n = (n+5+31) & (^31)
	return NewEncoderWithCommit(make([]byte, 5, n), func(data []byte) (size int, err error) {
        return s.write(data)
    })
}

func (s *transport) write(data []byte) (size int, err error) {
    bs := s.wc.BlockSize()
    if bs < 16 {
        bs = 16
    }

    padding := bs - (len(data) % bs)
    if padding < 4 {
        padding += bs
    }

    data[4] = byte(padding)
    data = append(data, rand(padding)...)
    bigendian.PutUint32(data, uint32(len(data)-4))

    var wseqb [4]byte
    bigendian.PutUint32(wseqb[:], s.wseq)
    s.wh.Reset()
    s.wh.Write(wseqb[:])
    s.wh.Write(data)
    mac := s.wh.Sum(nil)

    s.wc.CryptBlocks(data, data)

    data = append(data, mac...)

    size, err = s.conn.Write(data)

    s.wseq++
    return
}

func (s *transport) writeKexInit() {
	p := NewEncoder()
	p.Byte(MsgKexinit).Bytes(rand(16))
	p.U32String(NameListKexAlgorithms).U32String(NameListServerHostKeyAlgorithms)
	p.U32String(NameListEncryptionAlgorithms1).U32String(NameListEncryptionAlgorithms2)
	p.U32String(NameListMacAlgorithms1).U32String(NameListMacAlgorithms2)
	p.U32String(NameListCompressionAlgorithms1).U32String(NameListCompressionAlgorithms2)
	p.U32String(NameListLanguages1).U32String(NameListLanguages2)
	p.Byte(0).U32(0)
	s.ckex = p.Out()

	s.Packet().Bytes(s.ckex).Commit()
}

type kexres struct {
	Kex, Shk, EncCS, EncSC, MacCS, MacSC, ComCS, ComSC string
}

func (s *transport) parseKexinit(b []byte) (*kexres, error) {
    s.skex = make([]byte, len(b))
    copy(s.skex, b)
    b = b[1:]

	var cookie []byte
	var kex, shk, ecs, esc, mcs, msc, ccs, csc, lcs, lsc string
	var follows byte
	var reserved uint32

	p := NewDecoder(b).NBytes(16, &cookie)
	p.U32String(&kex).U32String(&shk)
	p.U32String(&ecs).U32String(&esc)
	p.U32String(&mcs).U32String(&msc)
	p.U32String(&ccs).U32String(&csc)
	p.U32String(&lcs).U32String(&lsc)
	p.Byte(&follows).U32(&reserved).End()

	guessed := true
	var r kexres
	var g bool
	var err error

	r.Kex, g, err = namelistCheck(NameListKexAlgorithms, kex)
	if err != nil {
		return nil, err
	}
	guessed = g && guessed

	r.Shk, g, err = namelistCheck(NameListServerHostKeyAlgorithms, shk)
	if err != nil {
		return nil, err
	}
	guessed = g && guessed

	r.EncCS, g, err = namelistCheck(NameListEncryptionAlgorithms1, ecs)
	if err != nil {
		return nil, err
	}
	guessed = g && guessed
	r.EncSC, g, err = namelistCheck(NameListEncryptionAlgorithms2, esc)
	if err != nil {
		return nil, err
	}
	guessed = g && guessed

	r.MacCS, g, err = namelistCheck(NameListMacAlgorithms1, mcs)
	if err != nil {
		return nil, err
	}
	guessed = g && guessed
	r.MacSC, g, err = namelistCheck(NameListMacAlgorithms2, msc)
	if err != nil {
		return nil, err
	}
	guessed = g && guessed

	r.ComCS, g, err = namelistCheck(NameListCompressionAlgorithms1, ccs)
	if err != nil {
		return nil, err
	}
	guessed = g && guessed
	r.ComSC, g, err = namelistCheck(NameListCompressionAlgorithms2, csc)
	if err != nil {
		return nil, err
	}
	guessed = g && guessed

	if !guessed && (follows > 0) {
		<-s.packets
	}

	return &r, nil
}
