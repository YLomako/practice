package dnstunnel

import "strings"

type lengthChecker struct{}

func newLengthChecker() *lengthChecker {
	return &lengthChecker{}
}

func (l *lengthChecker) Check(domain string, threshold int) (bool, int) {
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return false, 0
	}
	subdomain := parts[0]
	length := len(subdomain)

	// Добавим вывод для отладки (потом уберем)
	println("DEBUG: domain=", domain, "subdomain=", subdomain, "length=", length, "threshold=", threshold)

	return length > threshold, length
}
