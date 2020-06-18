package netlink

import "net"

// SocketID identifies a single socket.
type SocketID struct {
	SourcePort      uint16
	DestinationPort uint16
	Source          net.IP
	Destination     net.IP
	Interface       uint32
	Cookie          [2]uint32
}

// Socket represents a netlink socket.
type Socket struct {
	Family  uint8    `json:"family"`
	State   uint8    `json:"state"`
	Timer   uint8    `json:"timer"`
	Retrans uint8    `json:"retrans"`
	ID      SocketID `json:"id"`
	Expires uint32   `json:"expires"`
	RQueue  uint32   `json:"rqueue"`
	WQueue  uint32   `json:"wqueue"`
	UID     uint32   `json:"uid"`
	INode   uint32   `json:"inode"`
}
