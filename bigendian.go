package ssh

import (
    "encoding/binary"
)

var bigendian = binary.BigEndian

// Printer type. Don't touch the internals.
type Printer struct {
	W []byte
}

// Create a new printer with empty output.
func NewPrinter() *Printer {
	return &Printer{[]byte{}}
}

// Create a new printer with output prefixed with the given byte slice.
func NewPrinterWith(b []byte) *Printer {
	return &Printer{b}
}

// Output a byte.
func (p *Printer) Byte(d byte) *Printer {
	p.W = append(p.W, d)
	return p
}

// Output 2 bigendian bytes.
func (p *Printer) U16(d uint16) *Printer {
	p.W = append(p.W, byte(d>>8), byte(d))
	return p
}

// Output 4 bigendian bytes.
func (p *Printer) U32(d uint32) *Printer {
	p.W = append(p.W, byte(d>>24), byte(d>>16), byte(d>>8), byte(d))
	return p
}

// Output 4 bigendian bytes.
func (p *Printer) U64(d uint64) *Printer {
	p.W = append(p.W, byte(d>>56), byte(d>>48), byte(d>>40), byte(d>>32), byte(d>>24), byte(d>>16), byte(d>>8), byte(d))
	return p
}

// Output a raw byte slice with no length prefix.
func (p *Printer) Bytes(d []byte) *Printer {
	p.W = append(p.W, d...)
	return p
}

// Output a raw string with no length prefix.
func (p *Printer) String(d string) *Printer {
	p.W = append(p.W, []byte(d)...)
	return p
}

// Output a string with a 4 byte bigendian length prefix and no trailing null.
func (p *Printer) U32String(d string) *Printer {
	return p.U32(uint32(len(d))).String(d)
}

// Output bytes with a 4 byte bigendian length prefix and no trailing null.
func (p *Printer) U32Bytes(d []byte) *Printer {
	return p.U32(uint32(len(d))).Bytes(d)
}

// Output a string with a 2 byte bigendian length prefix and no trailing null.
func (p *Printer) U16String(d string) *Printer {
	if len(d) > 0xffff {
		panic("binprinter: string too long")
	}
	return p.U16(uint16(len(d))).String(d)
}

// Output a string with a 1 byte bigendian length prefix and no trailing null.
func (p *Printer) U8String(d string) *Printer {
	if len(d) > 0xff {
		panic("binprinter: string too long")
	}
	return p.Byte(byte(len(d))).String(d)
}

// Output a string terminated by a null-byte
func (p *Printer)String0(d string) *Printer {
	return p.String(d).Byte(0)
}

// Get the output as a byte slice.
func (p *Printer) Out() []byte {
	return p.W
}

// Parser type. Don't touch the internals.
type Parser struct {
	R   []byte
	Off int
}

// Create a new parser with the given buffer.
func NewParser(b []byte) *Parser {
	return &Parser{b, 0}
}

// Parse a byte from the buffer.
func (p *Parser) Byte(d *byte) *Parser {
	*d = p.R[p.Off]
	p.Off++
	return p
}

// Parse 2 bigendian bytes from the buffer.
func (p *Parser) U16(d *uint16) *Parser {
	*d = bigendian.Uint16(p.R[p.Off:])
	p.Off += 2
	return p
}

// Parse 4 bigendian bytes from the buffer.
func (p *Parser) U32(d *uint32) *Parser {
	*d = bigendian.Uint32(p.R[p.Off:])
	p.Off += 4
	return p
}
// Parse 8 bigendian bytes from the buffer.
func (p *Parser) U64(d *uint64) *Parser {
	*d = bigendian.Uint64(p.R[p.Off:])
	p.Off += 8
	return p
}

// Parse n bytes from the buffer to a []byte pointer.
func (p *Parser) NBytes(n int, d *[]byte) *Parser {
	if n > len(p.R[p.Off:]) {
		panic("binparser: overflowing length")
	}
	*d = make([]byte, n)
	copy(*d, p.R[p.Off:])
	p.Off += n
	return p
}

// Parse a string with a 4 byte bigendian length prefix to a []byte pointer.
func (p *Parser) U32Bytes(d *[]byte) *Parser {
	var v uint32
	return p.U32(&v).NBytes(int(v), d)
}

// Parse n bytes from the buffer to a string pointer.
func (p *Parser) NString(n int, d *string) *Parser {
	if n > len(p.R[p.Off:]) {
		panic("binparser: overflowing length")
	}
	b := make([]byte, n)
	copy(b, p.R[p.Off:])
	*d = string(b)
	p.Off += n
	return p
}

// Parse a string with a 4 byte bigendian length prefix to a string pointer.
func (p *Parser) U32String(d *string) *Parser {
	var v uint32
	return p.U32(&v).NString(int(v), d)
}

// Parse a string with a 2 byte bigendian length prefix to a string pointer.
func (p *Parser) U16String(d *string) *Parser {
	var v uint16
	return p.U16(&v).NString(int(v), d)
}

// Parse a string with a 1 byte length prefix to a string pointer.
func (p *Parser) U8String(d *string) *Parser {
	var v uint8
	return p.Byte(&v).NString(int(v), d)
}

// Parse a null terminated string.
func (p *Parser) String0(d *string) *Parser {
	for i,ch := range p.R[p.Off:] {
		if ch == 0 {
			p.NString(i, d)
			p.Off++
			return p
		}
	}
	panic("String0: null byte not found")
}

// Check that we are at the end of input.
func (p *Parser) End() {
	if p.Off != len(p.R) {
		panic("binparser: overlong packet")
	}
}

// Check that we are at the end of input.
func (p *Parser) AtEnd() bool {
	return p.Off == len(p.R)
}

// Peek the rest of input as raw bytes.
func (p *Parser) PeekRest(d *[]byte) *Parser {
	*d = p.R[p.Off:]
	return p
}
