package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestApplicationNetworkPolicy_Creation(t *testing.T) {
	anp := &ApplicationNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-anp",
			Namespace: "default",
		},
		Spec: ApplicationNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networking.PolicyType{networking.PolicyTypeEgress},
			Egress: []ApplicationNetworkPolicyEgressRule{
				{
					DomainNames: []DomainName{"example.com", "*.amazonaws.com"},
					Ports: []networking.NetworkPolicyPort{
						{Port: &intstr.IntOrString{IntVal: 443}},
					},
				},
			},
		},
	}

	assert.Equal(t, "test-anp", anp.Name)
	assert.Equal(t, "default", anp.Namespace)
	assert.Equal(t, 1, len(anp.Spec.Egress))
	assert.Equal(t, 2, len(anp.Spec.Egress[0].DomainNames))
	assert.Equal(t, DomainName("example.com"), anp.Spec.Egress[0].DomainNames[0])
	assert.Equal(t, DomainName("*.amazonaws.com"), anp.Spec.Egress[0].DomainNames[1])
}

func TestDomainName_Validation(t *testing.T) {
	tests := []struct {
		name   string
		domain DomainName
		valid  bool
	}{
		{"exact match", "example.com", true},
		{"wildcard subdomain", "*.example.com", true},
		{"kubernetes domain", "kubernetes.io", true},
		{"aws domain", "amazonaws.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation - domain name should not be empty
			assert.NotEmpty(t, string(tt.domain))
		})
	}
}

func TestApplicationNetworkPolicyEgressRule_MutualExclusivity(t *testing.T) {
	// Test that we can create rules with either To or DomainNames, but the validation
	// will be handled at the resolver level

	// Rule with CIDR
	cidrRule := ApplicationNetworkPolicyEgressRule{
		To: []networking.NetworkPolicyPeer{
			{
				IPBlock: &networking.IPBlock{CIDR: "10.0.0.0/8"},
			},
		},
	}
	assert.Equal(t, 1, len(cidrRule.To))
	assert.Equal(t, 0, len(cidrRule.DomainNames))

	// Rule with FQDN
	fqdnRule := ApplicationNetworkPolicyEgressRule{
		DomainNames: []DomainName{"example.com"},
	}
	assert.Equal(t, 0, len(fqdnRule.To))
	assert.Equal(t, 1, len(fqdnRule.DomainNames))
}
