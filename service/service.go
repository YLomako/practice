package service

import (
	"Firewall/models"
	"Firewall/repository"
	"Firewall/service/dnstunnel"
	"Firewall/utils"
	"fmt"
	"log"
	"net"
	"time"
)

type FirewallService interface {
	StartFirewall() error
	StopFirewall()
	AddRule(rule models.Rule) error
	RemoveRule(id string) error
	GetRules() ([]models.Rule, error)
	CheckPacket(packet models.PacketInfo) (bool, error)
	GetStats() FirewallStats
	GetDNSDetector() dnstunnel.Detector
}

type FirewallStats struct {
	PacketsProcessed int64
	PacketsBlocked   int64
	PacketsAllowed   int64
	StartTime        time.Time
}

type firewallService struct {
	repo          repository.RuleRepository
	running       bool
	stopChan      chan struct{}
	stats         FirewallStats
	packetHandler *utils.PacketHandler
	dnsDetector   dnstunnel.Detector
}

func NewFirewallService(repo repository.RuleRepository) FirewallService {
	// СОЗДАЕМ КОНФИГ ДЛЯ DNS-ДЕТЕКТОРА
	dnsConfig := dnstunnel.Config{
		LengthThreshold:    100,
		EntropyThreshold:   3.5,
		EnableLengthCheck:  true,
		EnableEntropyCheck: true,
		EnableBeaconCheck:  false,
		BlockDuration:      300,
		LogAllQueries:      false,
	}

	dnsDetector := dnstunnel.NewDetector(dnsConfig)

	return &firewallService{
		repo:     repo,
		stopChan: make(chan struct{}),
		stats: FirewallStats{
			StartTime: time.Now(),
		},
		dnsDetector: dnsDetector,
	}
}

// 🔥 ИСПРАВЛЕННАЯ ФУНКЦИЯ StartFirewall
func (s *firewallService) StartFirewall() error {
	if s.running {
		return fmt.Errorf("firewall is already running")
	}

	s.running = true
	s.stats.StartTime = time.Now()

	// Инициализируем обработчик пакетов
	handler, err := utils.NewPacketHandler()
	if err != nil {
		return fmt.Errorf("failed to initialize packet handler: %v", err)
	}
	s.packetHandler = handler

	// 🔥 ВАЖНО: ЗАПУСКАЕМ СЛУШАТЕЛИ НА ПОРТУ 5353
	log.Println("🚀 Запускаем слушатели пакетов на порту 5354...")
	err = s.packetHandler.StartListening(5354)
	if err != nil {
		return fmt.Errorf("failed to start packet listener: %v", err)
	}
	log.Println("✅ Слушатели пакетов запущены успешно")

	go s.packetProcessingLoop()

	log.Println("🔥 Firewall started successfully")
	return nil
}

func (s *firewallService) StopFirewall() {
	if !s.running {
		return
	}

	close(s.stopChan)
	s.running = false

	if s.packetHandler != nil {
		s.packetHandler.Close()
	}

	log.Println("Firewall stopped")
}

func (s *firewallService) AddRule(rule models.Rule) error {
	if rule.ID == "" {
		rule.ID = fmt.Sprintf("rule_%d", time.Now().UnixNano())
	}
	rule.CreatedAt = time.Now()

	// Валидация правил
	if rule.Port < 0 || rule.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", rule.Port)
	}

	switch rule.Protocol {
	case "tcp", "udp", "both":
		// valid
	default:
		return fmt.Errorf("invalid protocol: %s", rule.Protocol)
	}

	switch rule.Action {
	case "allow", "deny":
		// valid
	default:
		return fmt.Errorf("invalid action: %s", rule.Action)
	}

	switch rule.Direction {
	case "inbound", "outbound", "both":
		// valid
	default:
		return fmt.Errorf("invalid direction: %s", rule.Direction)
	}

	return s.repo.AddRule(rule)
}

func (s *firewallService) RemoveRule(id string) error {
	return s.repo.RemoveRule(id)
}

func (s *firewallService) GetRules() ([]models.Rule, error) {
	return s.repo.GetAllRules()
}

func (s *firewallService) CheckPacket(packet models.PacketInfo) (bool, error) {
	s.stats.PacketsProcessed++

	// Получаем все правила для порта назначения
	rules, err := s.repo.GetRulesByPort(packet.DestinationPort)
	if err != nil {
		return false, err
	}

	// Также проверяем правила для исходного порта (для исходящего трафика)
	if packet.SourcePort > 0 {
		sourceRules, err := s.repo.GetRulesByPort(packet.SourcePort)
		if err != nil {
			return false, err
		}
		rules = append(rules, sourceRules...)
	}

	// Если нет правил для этого порта, разрешаем трафик
	if len(rules) == 0 {
		s.stats.PacketsAllowed++
		return true, nil
	}

	// Проверяем правила
	for _, rule := range rules {
		// Проверяем протокол
		if rule.Protocol != "both" && rule.Protocol != packet.Protocol {
			continue
		}

		// Проверяем направление
		if rule.Direction != "both" {
			packetDirection := s.determinePacketDirection(packet)
			if rule.Direction != packetDirection {
				continue
			}
		}

		// Проверяем порт
		if rule.Port == packet.DestinationPort || rule.Port == packet.SourcePort {
			switch rule.Action {
			case "allow":
				s.stats.PacketsAllowed++
				return true, nil
			case "deny":
				s.stats.PacketsBlocked++
				log.Printf("Packet blocked by rule %s: %+v", rule.ID, packet)
				return false, nil
			}
		}
	}

	// По умолчанию разрешаем трафик
	s.stats.PacketsAllowed++
	return true, nil
}

func (s *firewallService) determinePacketDirection(packet models.PacketInfo) string {
	localIPs := s.getLocalIPs()

	for _, localIP := range localIPs {
		if packet.DestinationIP == localIP {
			return "inbound"
		}
		if packet.SourceIP == localIP {
			return "outbound"
		}
	}

	return "unknown"
}

func (s *firewallService) getLocalIPs() []string {
	var ips []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			ip = ip.To4()
			if ip == nil {
				continue
			}

			ips = append(ips, ip.String())
		}
	}

	return ips
}

func (s *firewallService) packetProcessingLoop() {
	if s.packetHandler == nil {
		return
	}

	log.Println("🔄 Packet processing loop started")

	for {
		select {
		case <-s.stopChan:
			log.Println("🛑 Packet processing loop stopped")
			return
		case packet := <-s.packetHandler.Packets():
			log.Printf("📦 Получен пакет: %s:%d -> %s:%d",
				packet.SourceIP, packet.SourcePort,
				packet.DestinationIP, packet.DestinationPort)

			allowed, err := s.CheckPacket(packet)
			if err != nil {
				log.Printf("❌ Error checking packet: %v", err)
				continue
			}

			// 🔥 АНАЛИЗИРУЕМ ДАННЫЕ ПАКЕТА
			if len(packet.Data) > 0 {
				domain := string(packet.Data)
				log.Printf("🔍 Анализируем данные: %s", domain)

				alert, err := s.dnsDetector.Analyze(packet.SourceIP, domain)
				if err != nil {
					log.Printf("❌ Ошибка детектора: %v", err)
				} else if alert != nil {
					log.Printf("⚠️ СОЗДАН АЛЕРТ: %s от %s (домен: %s)",
						alert.Severity, alert.SourceIP, domain)

					if alert.Severity == dnstunnel.AlertHigh ||
						alert.Severity == dnstunnel.AlertCritical {
						allowed = false
						log.Printf("🛑 Блокируем IP %s", packet.SourceIP)
					}
				}
			}

			// Применяем решение
			if !allowed {
				s.packetHandler.BlockPacket(packet)
				log.Printf("🚫 Пакет ЗАБЛОКИРОВАН")
			} else {
				s.packetHandler.AllowPacket(packet)
				log.Printf("✅ Пакет РАЗРЕШЕН")
			}
		}
	}
}

func (s *firewallService) GetStats() FirewallStats {
	return s.stats
}

func (s *firewallService) GetDNSDetector() dnstunnel.Detector {
	return s.dnsDetector
}
