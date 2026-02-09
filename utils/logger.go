package utils

import (
	"Firewall/models"
	"fmt"
	"log"
	"net"
	"sync"
)

type PacketHandler struct {
    packets   chan models.PacketInfo
    stopChan  chan struct{}
    listeners []net.Listener
    mu        sync.Mutex
}

func NewPacketHandler() (*PacketHandler, error) {
    return &PacketHandler{
        packets:  make(chan models.PacketInfo, 1000),
        stopChan: make(chan struct{}),
    }, nil
}

func (h *PacketHandler) StartListening(port int) error {
    h.mu.Lock()
    defer h.mu.Unlock()
    
    // TCP listener
    tcpAddr := fmt.Sprintf(":%d", port)
    tcpListener, err := net.Listen("tcp", tcpAddr)
    if err != nil {
        return fmt.Errorf("failed to start TCP listener: %v", err)
    }
    
    // UDP listener
    udpAddr, err := net.ResolveUDPAddr("udp", tcpAddr)
    if err != nil {
        tcpListener.Close()
        return fmt.Errorf("failed to resolve UDP address: %v", err)
    }
    
    udpListener, err := net.ListenUDP("udp", udpAddr)
    if err != nil {
        tcpListener.Close()
        return fmt.Errorf("failed to start UDP listener: %v", err)
    }
    
    h.listeners = append(h.listeners, tcpListener)
    
    go h.handleTCPConnections(tcpListener)
    go h.handleUDPPackets(udpListener)
    
    log.Printf("Started listening on port %d", port)
    return nil
}

func (h *PacketHandler) handleTCPConnections(listener net.Listener) {
    defer listener.Close()
    
    for {
        select {
        case <-h.stopChan:
            return
        default:
            conn, err := listener.Accept()
            if err != nil {
                continue
            }
            
            go h.processTCPConnection(conn)
        }
    }
}

func (h *PacketHandler) processTCPConnection(conn net.Conn) {
    defer conn.Close()
    
    remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
    localAddr := conn.LocalAddr().(*net.TCPAddr)
    
    packet := models.PacketInfo{
        SourceIP:        remoteAddr.IP.String(),
        SourcePort:      remoteAddr.Port,
        DestinationIP:   localAddr.IP.String(),
        DestinationPort: localAddr.Port,
        Protocol:        "tcp",
    }
    
    select {
    case h.packets <- packet:
        // Пакет отправлен на проверку
    default:
        log.Println("Packet channel is full")
    }
}

func (h *PacketHandler) handleUDPPackets(conn *net.UDPConn) {
    defer conn.Close()
    
    buffer := make([]byte, 1024)
    
    for {
        select {
        case <-h.stopChan:
            return
        default:
            n, remoteAddr, err := conn.ReadFromUDP(buffer)
            if err != nil {
                continue
            }
            
            localAddr := conn.LocalAddr().(*net.UDPAddr)
            
            packet := models.PacketInfo{
                SourceIP:        remoteAddr.IP.String(),
                SourcePort:      remoteAddr.Port,
                DestinationIP:   localAddr.IP.String(),
                DestinationPort: localAddr.Port,
                Protocol:        "udp",
            }
            
            select {
            case h.packets <- packet:
                // Пакет отправлен на проверку
            default:
                log.Println("Packet channel is full")
            }
            
            // Отправляем ответ (для простоты эхо)
            if n > 0 {
                conn.WriteToUDP(buffer[:n], remoteAddr)
            }
        }
    }
}

func (h *PacketHandler) Packets() <-chan models.PacketInfo {
    return h.packets
}

func (h *PacketHandler) BlockPacket(packet models.PacketInfo) {
    log.Printf("Blocking packet: %s:%d -> %s:%d (%s)",
        packet.SourceIP, packet.SourcePort,
        packet.DestinationIP, packet.DestinationPort,
        packet.Protocol)
}

func (h *PacketHandler) AllowPacket(packet models.PacketInfo) {
    log.Printf("Allowing packet: %s:%d -> %s:%d (%s)",
        packet.SourceIP, packet.SourcePort,
        packet.DestinationIP, packet.DestinationPort,
        packet.Protocol)
}

func (h *PacketHandler) Close() {
    close(h.stopChan)
    
    h.mu.Lock()
    defer h.mu.Unlock()
    
    for _, listener := range h.listeners {
        listener.Close()
    }
    
    close(h.packets)
}