package ssh

import (
    "io"
    "os"
)

func Spawn(command string, in io.ReadCloser, out, err io.WriteCloser, noTTY bool) func(ch *Channel) {
    return func(ch *Channel) {
        /*if v.In == nil {
            v.In = os.Stdin
        }
        if v.Out == nil {
            v.Out = os.Stdout
        }
        if v.Err == nil {
            v.Err = os.Stderr
        }*/

        ch.OnChannelOpenConfirmation = func(ch *Channel) {
            c := ch.Client()
            if !noTTY {
                c.Packet().
                    Byte(MsgChannelRequest).U32(ch.remoteId).U32String("pty-req").
                    Byte(0).U32String(os.Getenv("TERM")).
                    U32(0).U32(0).U32(0).U32(0).U32String("").
                    Commit()
            }
            if len(command) == 0 {
                c.Packet().Byte(MsgChannelRequest).U32(ch.remoteId).U32String("shell").Byte(1).Commit()
            } else {
                c.Packet().Byte(MsgChannelRequest).U32(ch.remoteId).U32String("exec").Byte(1).U32String(command).Commit()
            }
        }

        /* ChanType:      "session",
           PeersId:       localId,
           PeersWindow:   1 << 14,
           MaxPacketSize: 1 << 15, // RFC 4253 6.1
        */

        //ch.Client().Packet().Byte(MsgChannelOpen).
        //    U32String("session").U32(ch.localId).U32(ch.localWindow).U32(MaxPacketSize).
        //    Commit()
    }
}
