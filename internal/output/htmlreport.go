package output

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func GenerateHTMLReport(report *Report, filename string) error {
	var sb strings.Builder
	
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aegis Vulnerability Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 30px; margin-bottom: 20px; text-align: center; }
        .header h1 { color: #58a6ff; font-size: 2.5em; margin-bottom: 10px; }
        .header .subtitle { color: #8b949e; font-size: 1.1em; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .summary-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }
        .summary-card .count { font-size: 2.5em; font-weight: bold; }
        .summary-card .label { color: #8b949e; margin-top: 5px; }
        .critical .count { color: #ff7b72; }
        .high .count { color: #ffa657; }
        .medium .count { color: #d29922; }
        .low .count { color: #58a6ff; }
        .info .count { color: #8b949e; }
        .finding { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 15px; }
        .finding.critical { border-left: 4px solid #ff7b72; }
        .finding.high { border-left: 4px solid #ffa657; }
        .finding.medium { border-left: 4px solid #d29922; }
        .finding.low { border-left: 4px solid #58a6ff; }
        .finding.info { border-left: 4px solid #8b949e; }
        .finding h3 { margin-bottom: 10px; }
        .finding .severity-badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: bold; margin-right: 10px; }
        .severity-badge.critical { background: #ff7b72; color: #0d1117; }
        .severity-badge.high { background: #ffa657; color: #0d1117; }
        .severity-badge.medium { background: #d29922; color: #0d1117; }
        .severity-badge.low { background: #58a6ff; color: #0d1117; }
        .severity-badge.info { background: #8b949e; color: #0d1117; }
        .finding .url { color: #58a6ff; font-family: monospace; margin: 10px 0; word-break: break-all; }
        .finding .description { color: #c9d1d9; margin: 10px 0; line-height: 1.6; }
        .finding .evidence { background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 15px; margin: 10px 0; font-family: monospace; font-size: 0.9em; overflow-x: auto; white-space: pre-wrap; }
        .finding .remediation { background: #1a3a1a; border: 1px solid #2ea043; border-radius: 4px; padding: 15px; margin: 10px 0; color: #7ee787; }
        .finding .tags { margin-top: 10px; }
        .finding .tag { display: inline-block; background: #21262d; border: 1px solid #30363d; border-radius: 12px; padding: 2px 8px; font-size: 0.8em; margin-right: 5px; color: #8b949e; }
        .footer { text-align: center; padding: 20px; color: #8b949e; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Aegis Vulnerability Report</h1>
            <div class="subtitle">Automated Web Application Security Scan</div>
            <div class="subtitle">Generated: ` + time.Now().Format("January 2, 2006 15:04:05") + `</div>
        </div>
        
        <div class="summary">
            <div class="summary-card"><div class="count">` + fmt.Sprintf("%d", report.Summary.Total) + `</div><div class="label">Total Findings</div></div>
            <div class="summary-card critical"><div class="count">` + fmt.Sprintf("%d", report.Summary.Critical) + `</div><div class="label">Critical</div></div>
            <div class="summary-card high"><div class="count">` + fmt.Sprintf("%d", report.Summary.High) + `</div><div class="label">High</div></div>
            <div class="summary-card medium"><div class="count">` + fmt.Sprintf("%d", report.Summary.Medium) + `</div><div class="label">Medium</div></div>
            <div class="summary-card low"><div class="count">` + fmt.Sprintf("%d", report.Summary.Low) + `</div><div class="label">Low</div></div>
            <div class="summary-card info"><div class="count">` + fmt.Sprintf("%d", report.Summary.Info) + `</div><div class="label">Info</div></div>
        </div>
`)

	// Sort findings by severity
	sorted := make([]*Vulnerability, len(report.Vulnerabilities))
	copy(sorted, report.Vulnerabilities)
	// Bubble sort by severity
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i].Severity > sorted[j].Severity {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	for _, v := range sorted {
		severityClass := strings.ToLower(v.Severity.String())
		sb.WriteString(fmt.Sprintf(`
        <div class="finding %s">
            <h3><span class="severity-badge %s">%s</span> %s</h3>
            <div class="url">🌐 %s</div>
            <div class="description">%s</div>
            <div class="evidence"><strong>🔍 Evidence:</strong>\n%s</div>
            <div class="remediation"><strong>✅ Remediation:</strong> %s</div>
            <div class="tags">`, severityClass, severityClass, v.Severity.String(), v.Name, v.URL, v.Description, v.Evidence.ProofOfConcept, v.Remediation))
		
		for _, tag := range v.Tags {
			sb.WriteString(fmt.Sprintf(`<span class="tag">%s</span> `, tag))
		}
		
		sb.WriteString(`</div></div>`)
	}

	sb.WriteString(`
        <div class="footer">
            <p>Generated by Aegis - Intelligent Web Vulnerability Hunter</p>
            <p>This report contains confidential security findings. Handle with care.</p>
        </div>
    </div>
</body>
</html>`)

	return os.WriteFile(filename, []byte(sb.String()), 0644)
}
