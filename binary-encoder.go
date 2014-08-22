package ssh

import (
    "encoding/binary"
    "errors"
)

var bigendian = binary.BigEndian

// Encoder type. Don't touch the internals.
type Encoder struct {
	buf []byte
	commit func([]byte) (int, error)
}

// Create a new printer with empty output.
func NewEncoder() *Encoder {
	return &Encoder{make([]byte, 0, 32), nil}
}

// Create a new printer with output prefixed with the given byte slice.
func NewEncoderWith(data []byte) *Encoder {
	return &Encoder{data, nil}
}

func NewEncoderWithCommit(data []byte, commit func([]byte) (int, error)) *Encoder {
	return &Encoder{data, commit}
}

// Output a byte.
func (p *Encoder) Byte(d byte) *Encoder {
	p.buf = append(p.buf, d)
	return p
}

// Output 2 bigendian bytes.
func (p *Encoder) U16(d uint16) *Encoder {
	p.buf = append(p.buf, byte(d>>8), byte(d))
	return p
}

// Output 4 bigendian bytes.
func (p *Encoder) U32(d uint32) *Encoder {
	p.buf = append(p.buf, byte(d>>24), byte(d>>16), byte(d>>8), byte(d))
	return p
}

// Output 4 bigendian bytes.
func (p *Encoder) U64(d uint64) *Encoder {
	p.buf = append(p.buf, byte(d>>56), byte(d>>48), byte(d>>40), byte(d>>32), byte(d>>24), byte(d>>16), byte(d>>8), byte(d))
	return p
}

// Output a raw byte slice with no length prefix.
func (p *Encoder) Bytes(d []byte) *Encoder {
	p.buf = append(p.buf, d...)
	return p
}

// Output a raw string with no length prefix.
func (p *Encoder) String(d string) *Encoder {
	p.buf = append(p.buf, []byte(d)...)
	return p
}

// Output a string with a 4 byte bigendian length prefix and no trailing null.
func (p *Encoder) U32String(d string) *Encoder {
	return p.U32(uint32(len(d))).String(d)
}

// Output bytes with a 4 byte bigendian length prefix and no trailing null.
func (p *Encoder) U32Bytes(d []byte) *Encoder {
	return p.U32(uint32(len(d))).Bytes(d)
}

// Output a string with a 2 byte bigendian length prefix and no trailing null.
func (p *Encoder) U16String(d string) *Encoder {
	if len(d) > 0xffff {
		panic(errors.New("string length overflows uint16"))
	}
	return p.U16(uint16(len(d))).String(d)
}

// Output a string with a 1 byte bigendian length prefix and no trailing null.
func (p *Encoder) U8String(d string) *Encoder {
	if len(d) > 0xff {
		panic(errors.New("string length overflows uint8"))
	}
	return p.Byte(byte(len(d))).String(d)
}

// Output a string terminated by a null-byte
func (p *Encoder)String0(d string) *Encoder {
	return p.String(d).Byte(0)
}

// Get the output as a byte slice.
func (p *Encoder) Out() []byte {
	return p.buf
}

func (p *Encoder) Commit() (int, error) {
    return p.commit(p.buf)
}
