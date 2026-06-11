package utils

import "math"

func ShannonEntropy(s string) float64 {
    if len(s) == 0 {
        return 0
    }
    freq := make(map[rune]float64)
    for _, c := range s {
        freq[c]++
    }
    var entropy float64
    invLength := 1.0 / float64(len(s))
    for _, count := range freq {
        p := count * invLength
        entropy -= p * math.Log2(p)
    }
    return entropy
}