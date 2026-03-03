package dnstunnel

import (
	"log"
	"sync"
	"time"
)

type Detector interface {
	Analyze(srcIP, domain string) (*DNSAlert, error)
	GetStats() DNSStats
	GetAlerts(limit int) []DNSAlert
	UpdateConfig(config Config)
}

type detector struct {
	config        Config
	alerts        []DNSAlert
	stats         DNSStats
	mu            sync.RWMutex
	lengthChecker *lengthChecker
	entropyCalc   *entropyCalculator
	// Добавляем поля для подсчета энтропии
	totalEntropySum float64
	entropyCount    int
}

func NewDetector(config Config) Detector {
	return &detector{
		config:        config,
		alerts:        make([]DNSAlert, 0),
		stats:         DNSStats{AlertsByType: make(map[string]int64)},
		lengthChecker: newLengthChecker(),
		entropyCalc:   newEntropyCalculator(),
	}
}

func (d *detector) Analyze(srcIP string, domain string) (*DNSAlert, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 🔥 НОВАЯ ОТЛАДКА С ИСПОЛЬЗОВАНИЕМ log
	log.Printf("🔍🔍🔍 АНАЛИЗ DNS: domain=%s, srcIP=%s", domain, srcIP)
	log.Printf("🔍 Конфиг: LengthCheck=%v, EntropyCheck=%v, LengthThreshold=%d, EntropyThreshold=%.2f",
		d.config.EnableLengthCheck, d.config.EnableEntropyCheck,
		d.config.LengthThreshold, d.config.EntropyThreshold)

	d.stats.TotalQueries++

	details := make(map[string]interface{})
	reasons := []string{}
	severity := AlertLow

	// Оставляем старую отладку для консоли
	println("\n=== ANALYZE CALLED ===")
	println("Domain:", domain)
	println("Source IP:", srcIP)
	println("Config - LengthCheck:", d.config.EnableLengthCheck, "Threshold:", d.config.LengthThreshold)
	println("Config - EntropyCheck:", d.config.EnableEntropyCheck, "Threshold:", d.config.EntropyThreshold)

	var currentEntropy float64
	if d.config.EnableLengthCheck {
		suspicious, length := d.lengthChecker.Check(domain, d.config.LengthThreshold)
		println("Length check - suspicious:", suspicious, "length:", length, "threshold:", d.config.LengthThreshold)
		if suspicious {
			reasons = append(reasons, "long subdomain")
			details["length"] = length
			severity = AlertMedium
			println("✅ Length triggered")
		} else {
			println("❌ Length not triggered")
		}
	}

	if d.config.EnableEntropyCheck {
		suspicious, entropy := d.entropyCalc.Check(domain, d.config.EntropyThreshold)
		currentEntropy = entropy
		println("Entropy check - suspicious:", suspicious, "entropy:", entropy, "threshold:", d.config.EntropyThreshold)
		if suspicious {
			reasons = append(reasons, "high entropy")
			details["entropy"] = entropy
			if severity < AlertHigh {
				severity = AlertHigh
			}
			println("✅ Entropy triggered")
		} else {
			println("❌ Entropy not triggered")
		}
	}

	// Обновляем статистику энтропии для ВСЕХ запросов
	if currentEntropy > 0 {
		d.totalEntropySum += currentEntropy
		d.entropyCount++

		if currentEntropy > d.stats.MaxEntropy {
			d.stats.MaxEntropy = currentEntropy
		}
	}

	println("Reasons count:", len(reasons))
	for i, r := range reasons {
		println("Reason", i, ":", r)
	}

	if len(reasons) == 0 {
		println("No reasons - returning nil")
		log.Printf("✅ Нормальный DNS: %s от %s", domain, srcIP)
		return nil, nil
	}

	println("Creating alert with severity:", severity)

	alert := &DNSAlert{
		ID:          generateID(),
		Timestamp:   time.Now(),
		SourceIP:    srcIP,
		Domain:      domain,
		Severity:    severity,
		Reason:      joinReasons(reasons),
		Details:     details,
		ActionTaken: "logged",
	}

	d.alerts = append([]DNSAlert{*alert}, d.alerts...)
	if len(d.alerts) > 1000 {
		d.alerts = d.alerts[:1000]
	}

	d.stats.TotalAlerts++
	d.stats.AlertsByType[string(severity)]++

	println("Alert created successfully, total alerts:", d.stats.TotalAlerts)
	println("========================\n")

	log.Printf("⚠️ СОЗДАН АЛЕРТ: severity=%s, domain=%s, reasons=%s",
		severity, domain, joinReasons(reasons))

	return alert, nil
}

func (d *detector) GetStats() DNSStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	stats := d.stats

	// Вычисляем среднюю энтропию
	if d.entropyCount > 0 {
		stats.AvgEntropy = d.totalEntropySum / float64(d.entropyCount)
	}

	return stats
}

func (d *detector) GetAlerts(limit int) []DNSAlert {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if limit > len(d.alerts) {
		limit = len(d.alerts)
	}
	return d.alerts[:limit]
}

func (d *detector) UpdateConfig(config Config) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.config = config
}

// Вспомогательные функции
func generateID() string {
	return time.Now().Format("150405") + randomString(4)
}

func randomString(n int) string {
	letters := "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}

func joinReasons(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	if len(reasons) == 1 {
		return reasons[0]
	}
	result := ""
	for i, r := range reasons {
		if i > 0 {
			result += ", "
		}
		result += r
	}
	return result
}
