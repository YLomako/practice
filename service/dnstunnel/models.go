package dnstunnel

import "time"

type AlertSeverity string

const (
	AlertLow      AlertSeverity = "low"
	AlertMedium   AlertSeverity = "medium"
	AlertHigh     AlertSeverity = "high"
	AlertCritical AlertSeverity = "critical"
)

type DNSAlert struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	SourceIP    string                 `json:"source_ip"`
	Domain      string                 `json:"domain"`
	Severity    AlertSeverity          `json:"severity"`
	Reason      string                 `json:"reason"`
	Details     map[string]interface{} `json:"details"`
	ActionTaken string                 `json:"action_taken"`
}

type DNSStats struct {
	TotalQueries int64            `json:"total_queries"`
	TotalAlerts  int64            `json:"total_alerts"`
	AlertsByType map[string]int64 `json:"alerts_by_type"`
	BlockedIPs   int64            `json:"blocked_ips"`
	AvgEntropy   float64          `json:"avg_entropy"`
	MaxEntropy   float64          `json:"max_entropy"`
}
