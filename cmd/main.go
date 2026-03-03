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
	fmt.Println("🔴🔴🔴 MAIN STARTED - 1 🔴🔴🔴")

	// Инициализация репозитория
	fmt.Println("🔴 Создаем репозиторий...")
	ruleRepo := repository.NewInMemoryRuleRepository()

	// Инициализация сервиса
	fmt.Println("🔴 Создаем firewall service...")
	firewallService := service.NewFirewallService(ruleRepo)

	fmt.Println("🔴 Создаем обработчики...")
	// Инициализация обработчиков
	firewallHandler := handler.NewFirewallHandler(firewallService)
	alertHandler := handler.NewAlertHandler(firewallService)

	fmt.Println("🔴 Настраиваем маршруты...")
	// API маршруты
	http.HandleFunc("/firewall/start", firewallHandler.StartFirewall)
	http.HandleFunc("/firewall/stop", firewallHandler.StopFirewall)
	http.HandleFunc("/firewall/rules/add", firewallHandler.AddRule)
	http.HandleFunc("/firewall/rules/remove", firewallHandler.RemoveRule)
	http.HandleFunc("/firewall/rules", firewallHandler.GetRules)
	http.HandleFunc("/firewall/statistics", firewallHandler.GetStats)
	http.HandleFunc("/firewall/check", firewallHandler.CheckPacket)

	// Маршруты для DNS-детектора
	http.HandleFunc("/api/alerts", alertHandler.GetAlerts)
	http.HandleFunc("/api/dns/stats", alertHandler.GetDNSStats)
	http.HandleFunc("/api/dns/config", alertHandler.UpdateDNSConfig)

	// 🔥 НОВОЕ: обслуживание статических файлов (веб-интерфейс)
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	fmt.Println("🔴🔴🔴 MAIN ГОТОВ К ЗАПУСКУ СЕРВЕРА - 2 🔴🔴🔴")
	fmt.Println("📊 Веб-интерфейс доступен по адресу: http://localhost:8080")

	// Старт сервера
	port := ":8080"
	fmt.Printf("🔴 Запускаем сервер на порту %s...\n", port)

	err := http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatal("🔴 ОШИБКА СЕРВЕРА:", err)
	}
}
