package overlay

import (
	"net"
)

type UDPListener interface {
	ListenUDP(port uint16) net.PacketConn
}
