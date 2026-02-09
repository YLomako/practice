package models

import "time"

type Rule struct {
    ID        string    `json:"id"`
    Port      int       `json:"port"`
    Protocol  string    `json:"protocol"` // "tcp", "udp", "both"
    Action    string    `json:"action"`   // "allow", "deny"
    Direction string    `json:"direction"` // "inbound", "outbound", "both"
    CreatedAt time.Time `json:"created_at"`
}

type PacketInfo struct {
    SourcePort      int    `json:"source_port"`
    DestinationPort int    `json:"destination_port"`
    Protocol        string `json:"protocol"`
    SourceIP        string `json:"source_ip"`
    DestinationIP   string `json:"destination_ip"`
}