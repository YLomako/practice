package main

import (
	"Firewall/handler"
	"Firewall/repository"
	"Firewall/service"
	"fmt"
	"log"
	"net/http"
)

func main() {
    // Инициализация репозитория
    ruleRepo := repository.NewInMemoryRuleRepository()
    
    // Инициализация сервиса
    firewallService := service.NewFirewallService(ruleRepo)
    
    // Инициализация обработчиков
    firewallHandler := handler.NewFirewallHandler(firewallService)
    
    // Настройка маршрутов
    http.HandleFunc("/firewall/start", firewallHandler.StartFirewall)
    http.HandleFunc("/firewall/stop", firewallHandler.StopFirewall)
    http.HandleFunc("/firewall/rules/add", firewallHandler.AddRule)
    http.HandleFunc("/firewall/rules/remove", firewallHandler.RemoveRule)
    http.HandleFunc("/firewall/rules", firewallHandler.GetRules)
    http.HandleFunc("/firewall/stats", firewallHandler.GetStats)
    http.HandleFunc("/firewall/check", firewallHandler.CheckPacket)
    
    // Старт сервера
    port := ":8080"
    fmt.Printf("Firewall API server started on http://localhost%s\n", port)
    fmt.Println("Endpoints:")
    fmt.Println("  POST   /firewall/start")
    fmt.Println("  POST   /firewall/stop")
    fmt.Println("  POST   /firewall/rules/add")
    fmt.Println("  DELETE /firewall/rules/remove?id=<rule_id>")
    fmt.Println("  GET    /firewall/rules")
    fmt.Println("  GET    /firewall/stats")
    fmt.Println("  POST   /firewall/check")
    
    if err := http.ListenAndServe(port, nil); err != nil {
        log.Fatal(err)
    }
}