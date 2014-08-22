package ssh

const (
    ident = "SSH-2.0-gossh_0.0"

    // RFC4252 (Authentication Protocol)/6
    MsgUserauthRequest = 50
    MsgUserauthFailure = 51
    MsgUserauthSuccess = 52
    MsgUserauthBanner  = 53

    // RFC4253 (Transport Layer Protocol)/12
    MsgDisconnect     = 1
    MsgIgnore         = 2
    MsgUnimplemented  = 3
    MsgDebug          = 4
    MsgServiceRequest = 5
    MsgServiceAccept  = 6
    MsgKexinit        = 20
    MsgNewkeys        = 21
    MsgKexdhInit      = 30
    MsgKexdhReply     = 31

    // RFC4253/6.1
    MaxPacketSize = 32768

    // RFC4254 (Connection Protocol)/9
    MsgGlobalRequest           = 80
    MsgRequestSuccess          = 81
    MsgRequestFailure          = 82
    MsgChannelOpen             = 90
    MsgChannelOpenConfirmation = 91
    MsgChannelOpenFailure      = 92
    MsgChannelWindowAdjust     = 93
    MsgChannelData             = 94
    MsgChannelExtendedData     = 95
    MsgChannelEOF              = 96
    MsgChannelClose            = 97
    MsgChannelRequest          = 98
    MsgChannelSuccess          = 99
    MsgChannelFailure          = 100

    NameListKexAlgorithms = "diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
    NameListServerHostKeyAlgorithms = "ssh-rsa"

    NameListEncryptionAlgorithms1 = "aes128-ctr,aes128-cbc"
    NameListEncryptionAlgorithms2 = "aes128-ctr,aes128-cbc"
    NameListMacAlgorithms1 = "hmac-sha1"
    NameListMacAlgorithms2 = "hmac-sha1"
    NameListCompressionAlgorithms1 = "none"
    NameListCompressionAlgorithms2 = "none"
    NameListLanguages1 = ""
    NameListLanguages2 = ""
)
