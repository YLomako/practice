package handler

import (
	"Firewall/models"
	"Firewall/service"
	"encoding/json"
	"net/http"
	"time"
)

type FirewallHandler struct {
    firewallService service.FirewallService
}

func NewFirewallHandler(firewallService service.FirewallService) *FirewallHandler {
    return &FirewallHandler{
        firewallService: firewallService,
    }
}

func (h *FirewallHandler) StartFirewall(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    err := h.firewallService.StartFirewall()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    response := map[string]string{"status": "firewall started"}
    jsonResponse(w, response)
}

func (h *FirewallHandler) StopFirewall(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    h.firewallService.StopFirewall()
    
    response := map[string]string{"status": "firewall stopped"}
    jsonResponse(w, response)
}

func (h *FirewallHandler) AddRule(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    var rule models.Rule
    if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    if err := h.firewallService.AddRule(rule); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    response := map[string]string{
        "status": "rule added",
        "id":     rule.ID,
    }
    jsonResponse(w, response)
}

func (h *FirewallHandler) RemoveRule(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodDelete {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    id := r.URL.Query().Get("id")
    if id == "" {
        http.Error(w, "Rule ID is required", http.StatusBadRequest)
        return
    }
    
    if err := h.firewallService.RemoveRule(id); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    response := map[string]string{"status": "rule removed"}
    jsonResponse(w, response)
}

func (h *FirewallHandler) GetRules(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    rules, err := h.firewallService.GetRules()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    jsonResponse(w, rules)
}

func (h *FirewallHandler) GetStats(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    stats := h.firewallService.GetStats()
    
    response := map[string]interface{}{
        "packets_processed": stats.PacketsProcessed,
        "packets_blocked":   stats.PacketsBlocked,
        "packets_allowed":   stats.PacketsAllowed,
        "uptime":            time.Since(stats.StartTime).String(),
        "start_time":        stats.StartTime.Format(time.RFC3339),
    }
    
    jsonResponse(w, response)
}

func (h *FirewallHandler) CheckPacket(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    var packet models.PacketInfo
    if err := json.NewDecoder(r.Body).Decode(&packet); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    allowed, err := h.firewallService.CheckPacket(packet)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    response := map[string]interface{}{
        "allowed": allowed,
        "packet":  packet,
    }
    
    jsonResponse(w, response)
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(data)
}
