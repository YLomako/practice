package handler

import (
	"Firewall/service"
	"Firewall/service/dnstunnel"
	"encoding/json"
	"net/http"
	"strconv"
)

type AlertHandler struct {
	firewallService service.FirewallService
}

func NewAlertHandler(firewallService service.FirewallService) *AlertHandler {
	return &AlertHandler{
		firewallService: firewallService,
	}
}

// GetAlerts возвращает последние DNS-алерты
func (h *AlertHandler) GetAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// Получаем детектор через метод интерфейса
	detector := h.firewallService.GetDNSDetector()
	
	// Получаем параметр limit
	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	
	alerts := detector.GetAlerts(limit)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

// GetDNSStats возвращает статистику DNS-детектора
func (h *AlertHandler) GetDNSStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	detector := h.firewallService.GetDNSDetector()
	stats := detector.GetStats()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// UpdateDNSConfig обновляет конфигурацию DNS-детектора
func (h *AlertHandler) UpdateDNSConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var config dnstunnel.Config
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	detector := h.firewallService.GetDNSDetector()
	detector.UpdateConfig(config)
	
	response := map[string]string{"status": "config updated"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}