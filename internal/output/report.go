package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

type Report struct {
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
	SummaryData     ReportSummary    `json:"summary"`
	mu              sync.Mutex
}

type ReportSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

func NewReport() *Report {
	return &Report{
		Vulnerabilities: make([]*Vulnerability, 0),
	}
}

func (r *Report) AddVulnerability(v *Vulnerability) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Vulnerabilities = append(r.Vulnerabilities, v)
	r.updateSummary()
}

func (r *Report) AddVulnerabilities(vulns ...*Vulnerability) {
	for _, v := range vulns {
		r.AddVulnerability(v)
	}
}

func (r *Report) updateSummary() {
	r.SummaryData = ReportSummary{}
	r.SummaryData.Total = len(r.Vulnerabilities)
	for _, v := range r.Vulnerabilities {
		switch v.Severity {
		case SeverityCritical:
			r.SummaryData.Critical++
		case SeverityHigh:
			r.SummaryData.High++
		case SeverityMedium:
			r.SummaryData.Medium++
		case SeverityLow:
			r.SummaryData.Low++
		case SeverityInfo:
			r.SummaryData.Info++
		}
	}
}

func (r *Report) PrintSummary() string {
	var sb strings.Builder
	sb.WriteString("\n" + strings.Repeat("=", 60) + "\n")
	sb.WriteString("  AEGIS - VULNERABILITY SCAN SUMMARY\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	sb.WriteString(fmt.Sprintf("  Total Findings: %d\n", r.SummaryData.Total))
	sb.WriteString(fmt.Sprintf("  Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d\n",
		r.SummaryData.Critical, r.SummaryData.High, r.SummaryData.Medium, r.SummaryData.Low, r.SummaryData.Info))
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	if r.SummaryData.Critical > 0 || r.SummaryData.High > 0 {
		sb.WriteString("\n  CRITICAL & HIGH FINDINGS:\n")
		for _, v := range r.Vulnerabilities {
			if v.Severity == SeverityCritical || v.Severity == SeverityHigh {
				sb.WriteString(fmt.Sprintf("  [!] [%s] %s - %s\n", v.Severity.String()[:1], v.Name, v.URL))
			}
		}
	}

	return sb.String()
}

func SaveReport(report *Report, filename string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}
