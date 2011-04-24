package ssh

const (
	ident = "SSH-2.0-gossh_0.0"

	msgIgnore          = 2
	msgServiceRequest  = 5
	msgServiceAccept   = 6

	msgKexInit         = 20
	msgNewkeys         = 21
	msgKexdhInit       = 30
	msgKexdhReply      = 31
	
	msgUserauthRequest = 50
	msgUserauthFailure = 51
	msgUserauthSuccess = 52
	msgUserauthBanner  = 53

	msgGlobalRequest   = 80
	msgRequestSuccess  = 81
	msgRequestFailure  = 82
	msgChannelOpen     = 90
	msgChannelOpenConfirmation = 91
	msgChannelOpenFailure      = 92
	msgChannelWindowAdjust     = 93
	msgChannelData             = 94
	msgChannelExtendedData     = 95
	msgChannelEof              = 96
	msgChannelClose            = 97
	msgChannelRequest          = 98
	msgChannelSuccess          = 99
	msgChannelFailure          = 100

	maxPacketData              = 32*1024*1024

	kexKex = "diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
	kexShk = "ssh-rsa"
	kexEnc = "aes128-ctr,aes128-cbc"
	kexMac = "hmac-sha1"
	kexCom = "none"
	kexLan = ""
)
