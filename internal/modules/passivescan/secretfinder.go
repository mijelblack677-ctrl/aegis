package passivescan

import (
	"fmt"
	"strings"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type SecretFinder struct{}

func NewSecretFinder() *SecretFinder {
	return &SecretFinder{}
}

func (sf *SecretFinder) Name() string    { return "secret_finder" }
func (sf *SecretFinder) IsPassive() bool { return true }

func (sf *SecretFinder) Run(pair *modules.RequestResponsePair) ([]*output.Vulnerability, error) {
	var vulns []*output.Vulnerability
	
	if pair.ParsedData == nil {
		return vulns, nil
	}
	
	for _, secret := range pair.ParsedData.Secrets {
		vuln := &output.Vulnerability{
			Name:        fmt.Sprintf("Hardcoded Secret Exposed: %s", secret.Type),
			Description: fmt.Sprintf("A secret of type '%s' was found in the response body. This could allow an attacker to gain unauthorized access to internal services.", secret.Type),
			Severity:    output.SeverityCritical,
			URL:         pair.Request.URL.String(),
			Evidence: output.Evidence{
				ProofOfConcept: fmt.Sprintf("The secret was found in %s: %s...", secret.Source, secret.Value[:min(20, len(secret.Value))]),
			},
			Remediation: "Remove the hardcoded secret and use environment variables or a secrets management service.",
			Tags:        []string{"secret-exposure", "goldmine", "passive"},
		}
		vulns = append(vulns, vuln)
	}
	
	return vulns, nil
}