package ssh

import (
)

// Do password authentication
func (c *Client) auth(user, pass string) bool {
	// Service request
	Log(5, "C->S: Service Request ssh-userauth")
	c.Packet().Byte(MsgServiceRequest).U32String("ssh-userauth").Commit()

	b := <-c.packets
	//if err != nil { panic(err) }

	var code byte
	var service string
	NewDecoder(b).Byte(&code).U32String(&service).End()
	if (code != MsgServiceAccept) || (service != "ssh-userauth") { panic("Expected MsgServiceAccept") }

	// Password authentication
	Log(5, "C->S: Userauth Request password")
	c.Packet().Byte(MsgUserauthRequest).U32String(user).U32String("ssh-connection").U32String("password").Byte(0).U32String(pass).Commit()
	b = <-c.packets
	return (len(b) == 1) && (b[0] == MsgUserauthSuccess)
}
