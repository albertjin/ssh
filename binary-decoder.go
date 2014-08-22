package ssh

import (
    "errors"
)

// Decoder type.
type Decoder struct {
    buf []byte
    offset int
}

// Create a new parser with the given buffer.
func NewDecoder(b []byte) *Decoder {
    return &Decoder{b, 0}
}

// Parse a byte from the buffer.
func (p *Decoder) Byte(d *byte) *Decoder {
    *d = p.buf[p.offset]
    p.offset++
    return p
}

// Parse 2 bigendian bytes from the buffer.
func (p *Decoder) U16(d *uint16) *Decoder {
    *d = bigendian.Uint16(p.buf[p.offset:])
    p.offset += 2
    return p
}

// Parse 4 bigendian bytes from the buffer.
func (p *Decoder) U32(d *uint32) *Decoder {
    *d = bigendian.Uint32(p.buf[p.offset:])
    p.offset += 4
    return p
}

// Parse 8 bigendian bytes from the buffer.
func (p *Decoder) U64(d *uint64) *Decoder {
    *d = bigendian.Uint64(p.buf[p.offset:])
    p.offset += 8
    return p
}

// Parse n bytes from the buffer to a []byte pointer.
func (p *Decoder) NBytes(n int, d *[]byte) *Decoder {
    *d = p.buf[p.offset:p.offset+n]
    p.offset += n
    return p
}

// Parse a string with a 4 byte bigendian length prefix to a []byte pointer.
func (p *Decoder) U32Bytes(d *[]byte) *Decoder {
    var n uint32
    return p.U32(&n).NBytes(int(n), d)
}

// Parse n bytes from the buffer to a string pointer.
func (p *Decoder) NString(n int, s *string) *Decoder {
    *s = string(p.buf[p.offset:p.offset+n])
    p.offset += n
    return p
}

// Parse a string with a 4 byte bigendian length prefix to a string pointer.
func (p *Decoder) U32String(d *string) *Decoder {
    var v uint32
    return p.U32(&v).NString(int(v), d)
}

// Parse a string with a 2 byte bigendian length prefix to a string pointer.
func (p *Decoder) U16String(d *string) *Decoder {
    var v uint16
    return p.U16(&v).NString(int(v), d)
}

// Parse a string with a 1 byte length prefix to a string pointer.
func (p *Decoder) U8String(d *string) *Decoder {
    var v uint8
    return p.Byte(&v).NString(int(v), d)
}

// Assert that we are at the end of input.
func (p *Decoder) End() {
    if !p.IsEnd() {
        panic(errors.New("packet has unparsed data"))
    }
}

// Query whether all data have been parsed.
func (p *Decoder) IsEnd() bool {
    return p.offset == len(p.buf)
}
