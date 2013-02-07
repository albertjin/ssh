package ssh

import (
)

// Do password authentication
func (c *ssh) password(user, pass string) bool {
	// Service request
	Log(5, "C->S: Service Request ssh-userauth")
	c.writePacket(func(p *Printer) { p.Byte(msgServiceRequest).U32String("ssh-userauth") })
	b, e := c.readPacket()
	if e != nil { panic(e) }
	var code byte
	var service string
	NewParser(b).Byte(&code).U32String(&service).End()
	if code!=msgServiceAccept || service!="ssh-userauth" { panic("Expected msgServiceAccept") }

	// Password authentication
	Log(5, "C->S: Userauth Request password")
	c.writePacket(func(p *Printer) {
		p.Byte(msgUserauthRequest).U32String(user).U32String("ssh-connection").U32String("password").Byte(0).U32String(pass)
	})
	b, e = c.readPacket()
	if e != nil { panic(e) }
	return len(b)==1 && b[0]==msgUserauthSuccess
}
