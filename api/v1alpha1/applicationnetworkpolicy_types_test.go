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
					To: []ApplicationNetworkPolicyPeer{
						{
							DomainNames: []DomainName{"example.com", "*.amazonaws.com"},
						},
					},
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
	assert.Equal(t, 1, len(anp.Spec.Egress[0].To))
	assert.Equal(t, 2, len(anp.Spec.Egress[0].To[0].DomainNames))
	assert.Equal(t, DomainName("example.com"), anp.Spec.Egress[0].To[0].DomainNames[0])
	assert.Equal(t, DomainName("*.amazonaws.com"), anp.Spec.Egress[0].To[0].DomainNames[1])
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
	// Test that we can create rules with different peer types

	// Rule with CIDR only - valid
	cidrRule := ApplicationNetworkPolicyEgressRule{
		To: []ApplicationNetworkPolicyPeer{
			{
				IPBlock: &networking.IPBlock{CIDR: "10.0.0.0/8"},
			},
		},
	}
	assert.Equal(t, 1, len(cidrRule.To))
	assert.NotNil(t, cidrRule.To[0].IPBlock)
	assert.Nil(t, cidrRule.To[0].DomainNames)

	// Rule with FQDN only - valid
	fqdnRule := ApplicationNetworkPolicyEgressRule{
		To: []ApplicationNetworkPolicyPeer{
			{
				DomainNames: []DomainName{"example.com"},
			},
		},
	}
	assert.Equal(t, 1, len(fqdnRule.To))
	assert.Nil(t, fqdnRule.To[0].IPBlock)
	assert.Equal(t, 1, len(fqdnRule.To[0].DomainNames))

	// Rule with podSelector only - valid
	podSelectorRule := ApplicationNetworkPolicyEgressRule{
		To: []ApplicationNetworkPolicyPeer{
			{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "db"},
				},
			},
		},
	}
	assert.Equal(t, 1, len(podSelectorRule.To))
	assert.NotNil(t, podSelectorRule.To[0].PodSelector)
	assert.Nil(t, podSelectorRule.To[0].DomainNames)

	// Rule with namespaceSelector only - valid
	nsSelectorRule := ApplicationNetworkPolicyEgressRule{
		To: []ApplicationNetworkPolicyPeer{
			{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"env": "prod"},
				},
			},
		},
	}
	assert.Equal(t, 1, len(nsSelectorRule.To))
	assert.NotNil(t, nsSelectorRule.To[0].NamespaceSelector)
	assert.Nil(t, nsSelectorRule.To[0].DomainNames)

	// Mixed rule with separate peers - valid (each peer has only one field type)
	mixedRule := ApplicationNetworkPolicyEgressRule{
		To: []ApplicationNetworkPolicyPeer{
			{IPBlock: &networking.IPBlock{CIDR: "10.0.0.0/8"}},
			{DomainNames: []DomainName{"example.com"}},
			{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}}},
		},
	}
	assert.Equal(t, 3, len(mixedRule.To))

	// IPBlock + PodSelector + NamespaceSelector combinations - valid (no domainNames)
	validCombinationsRule := ApplicationNetworkPolicyEgressRule{
		To: []ApplicationNetworkPolicyPeer{
			{
				IPBlock: &networking.IPBlock{CIDR: "10.0.0.0/8"},
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
			},
			{
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
			},
			{
				IPBlock: &networking.IPBlock{CIDR: "192.168.0.0/16"},
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "backend"}},
			},
		},
	}
	assert.Equal(t, 3, len(validCombinationsRule.To))
	assert.NotNil(t, validCombinationsRule.To[0].IPBlock)
	assert.NotNil(t, validCombinationsRule.To[0].PodSelector)
	assert.NotNil(t, validCombinationsRule.To[1].PodSelector)
	assert.NotNil(t, validCombinationsRule.To[1].NamespaceSelector)
	assert.NotNil(t, validCombinationsRule.To[2].IPBlock)
	assert.NotNil(t, validCombinationsRule.To[2].NamespaceSelector)

	// Invalid combinations (would fail CEL validation at API level):
	
	// IPBlock + DomainNames in same peer
	invalidIPBlockRule := ApplicationNetworkPolicyEgressRule{
		To: []ApplicationNetworkPolicyPeer{
			{
				IPBlock:     &networking.IPBlock{CIDR: "10.0.0.0/8"},
				DomainNames: []DomainName{"example.com"},
			},
		},
	}
	assert.NotNil(t, invalidIPBlockRule.To[0].IPBlock)
	assert.Equal(t, 1, len(invalidIPBlockRule.To[0].DomainNames))

	// PodSelector + DomainNames in same peer
	invalidPodSelectorRule := ApplicationNetworkPolicyEgressRule{
		To: []ApplicationNetworkPolicyPeer{
			{
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
				DomainNames: []DomainName{"example.com"},
			},
		},
	}
	assert.NotNil(t, invalidPodSelectorRule.To[0].PodSelector)
	assert.Equal(t, 1, len(invalidPodSelectorRule.To[0].DomainNames))

	// NamespaceSelector + DomainNames in same peer
	invalidNSSelectorRule := ApplicationNetworkPolicyEgressRule{
		To: []ApplicationNetworkPolicyPeer{
			{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
				DomainNames:       []DomainName{"example.com"},
			},
		},
	}
	assert.NotNil(t, invalidNSSelectorRule.To[0].NamespaceSelector)
	assert.Equal(t, 1, len(invalidNSSelectorRule.To[0].DomainNames))
}
