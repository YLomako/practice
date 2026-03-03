package dnstunnel

import (
	"math"
	"strings"
)

type entropyCalculator struct{}

func newEntropyCalculator() *entropyCalculator {
	return &entropyCalculator{}
}

func (e *entropyCalculator) ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	charCounts := make(map[rune]int)
	for _, char := range s {
		charCounts[char]++
	}

	var entropy float64
	for _, count := range charCounts {
		prob := float64(count) / float64(len(s))
		entropy -= prob * math.Log2(prob)
	}

	return entropy
}

func (e *entropyCalculator) Check(domain string, threshold float64) (bool, float64) {
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return false, 0
	}

	subdomain := parts[0]
	if len(subdomain) < 8 {
		return false, 0
	}

	entropy := e.ShannonEntropy(subdomain)
	return entropy > threshold, entropy
}
