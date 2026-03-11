package utils

import (
	"Firewall/models"
	"log"
	"net"
	"time"
)

type PacketHandler struct {
	packets  chan models.PacketInfo
	stopChan chan struct{}
	udpConn  *net.UDPConn
}

func NewPacketHandler() (*PacketHandler, error) {
	log.Println("📦 СОЗДАН PacketHandler")
	return &PacketHandler{
		packets:  make(chan models.PacketInfo, 1000),
		stopChan: make(chan struct{}),
	}, nil
}

func (h *PacketHandler) StartListening(port int) error {
	log.Printf("🎯 StartListening НА ПОРТУ %d", port)
	go h.startUDPListener(port)
	log.Printf("✅ UDP слушатель ЗАПУЩЕН на порту %d", port)
	return nil
}

func (h *PacketHandler) startUDPListener(port int) {
	log.Println("🔴🔴🔴 UDP ЛИСТЕНЕР ЗАПУЩЕН 🔴🔴🔴")

	addr := net.UDPAddr{
		Port: 0,
		IP:   net.ParseIP("::"),
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Printf("❌ ОШИБКА UDP: %v", err)
		return
	}

	h.udpConn = conn
	log.Printf("✅ UDP СОЕДИНЕНИЕ СОЗДАНО на порту %d", port)
	log.Printf("✅ Локальный адрес: %s", conn.LocalAddr().String())

	buffer := make([]byte, 2048)
	packetCount := 0

	for {
		select {
		case <-h.stopChan:
			log.Println("🛑 UDP ЛИСТЕНЕР ОСТАНОВЛЕН")
			if h.udpConn != nil {
				h.udpConn.Close()
			}
			return
		default:
			h.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, remoteAddr, err := h.udpConn.ReadFromUDP(buffer)

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("❌ Ошибка чтения: %v", err)
				continue
			}

			packetCount++
			log.Printf("📦 ПОЛУЧЕН ПАКЕТ #%d от %s, длина %d байт", packetCount, remoteAddr, n)

			// Создаем копию данных
			data := make([]byte, n)
			copy(data, buffer[:n])

			packet := models.PacketInfo{
				SourceIP:        remoteAddr.IP.String(),
				SourcePort:      remoteAddr.Port,
				DestinationIP:   "127.0.0.1",
				DestinationPort: port,
				Protocol:        "udp",
				Data:            data,
			}

			select {
			case h.packets <- packet:
				log.Printf("✅ Пакет #%d отправлен в канал", packetCount)
			default:
				log.Printf("❌ Канал переполнен")
			}
		}
	}
}

func (h *PacketHandler) Packets() <-chan models.PacketInfo {
	return h.packets
}

func (h *PacketHandler) BlockPacket(packet models.PacketInfo) {
	log.Printf("🚫 БЛОКИРОВКА: %s:%d", packet.SourceIP, packet.SourcePort)
}

func (h *PacketHandler) AllowPacket(packet models.PacketInfo) {
	log.Printf("✅ РАЗРЕШЕНИЕ: %s:%d", packet.SourceIP, packet.SourcePort)
}

func (h *PacketHandler) Close() {
	log.Println("🛑 Закрытие PacketHandler")
	close(h.stopChan)
	if h.udpConn != nil {
		h.udpConn.Close()
	}
	close(h.packets)
}
