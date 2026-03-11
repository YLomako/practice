package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	fmt.Println("🔵 ДЕМОНСТРАЦИЯ: ОТПРАВКА НА РАЗНЫЕ ПОРТЫ")
	fmt.Println("=========================================")

	// Подозрительный домен (высокая энтропия)
	evilDomain := "x9k2m4n7q8r3t5v1w2x2342342342342342346y8z0a1b2c3d4.evil.com"
	normalDomain := "google.com"

	// Тест 1: Нормальный домен на порт 5354
	fmt.Printf("\n1️⃣ Отправляем нормальный домен на порт 5354...\n")
	if err := sendUDP("[::1]:5354", []byte(normalDomain)); err != nil {
		fmt.Printf("❌ Ошибка: %v\n", err)
	} else {
		fmt.Printf("✅ Отправлено: %s\n", normalDomain)
	}
	time.Sleep(2 * time.Second)

	// Тест 2: Подозрительный домен на порт 5354
	fmt.Printf("\n2️⃣ Отправляем подозрительный домен на порт 5354...\n")
	if err := sendUDP("[::1]:5354", []byte(evilDomain)); err != nil {
		fmt.Printf("❌ Ошибка: %v\n", err)
	} else {
		fmt.Printf("✅ Отправлено: %s\n", evilDomain)
	}
	time.Sleep(2 * time.Second)

	// Тест 3: Подозрительный домен на порт 8080
	fmt.Printf("\n3️⃣ Отправляем подозрительный домен на порт 8080...\n")
	if err := sendUDP("[::1]:8080", []byte(evilDomain)); err != nil {
		fmt.Printf("❌ Ошибка: %v\n", err)
	} else {
		fmt.Printf("✅ Отправлено на порт 8080\n")
	}
	time.Sleep(2 * time.Second)

	// Тест 4: Подозрительный домен на порт 80
	fmt.Printf("\n4️⃣ Отправляем подозрительный домен на порт 80...\n")
	if err := sendUDP("[::1]:80", []byte(evilDomain)); err != nil {
		fmt.Printf("❌ Ошибка: %v\n", err)
	} else {
		fmt.Printf("✅ Отправлено на порт 80\n")
	}

	fmt.Println("\n📊 РЕЗУЛЬТАТЫ:")
	fmt.Println("  - Порт 5354 (нормальный) → НЕТ алерта")
	fmt.Println("  - Порт 5354 (подозрительный) → ДОЛЖЕН быть алерт")
	fmt.Println("  - Порт 8080 → НЕТ алерта (firewall игнорирует)")
	fmt.Println("  - Порт 80 → НЕТ алерта (firewall игнорирует)")
	fmt.Println("\n🔍 Проверьте:")
	fmt.Println("  curl.exe http://localhost:8080/api/alerts")
	fmt.Println("  curl.exe http://localhost:8080/firewall/statistics")
}

func sendUDP(address string, data []byte) error {
	conn, err := net.Dial("udp", address)
	if err != nil {
		return fmt.Errorf("не удалось подключиться к %s: %v", address, err)
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("ошибка отправки на %s: %v", address, err)
	}
	return nil
}
