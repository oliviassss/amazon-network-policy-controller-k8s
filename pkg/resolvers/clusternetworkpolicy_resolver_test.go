package resolvers

import (
	"context"
	"fmt"
	"testing"

	policyinfo "github.com/aws/amazon-network-policy-controller-k8s/api/v1alpha1"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// MockEndpointsResolver is a mock for the base EndpointsResolver
type MockEndpointsResolver struct {
	mock.Mock
}

func (m *MockEndpointsResolver) Resolve(ctx context.Context, policy *networking.NetworkPolicy) ([]policyinfo.EndpointInfo, []policyinfo.EndpointInfo, []policyinfo.PodEndpoint, error) {
	args := m.Called(ctx, policy)
	return args.Get(0).([]policyinfo.EndpointInfo), args.Get(1).([]policyinfo.EndpointInfo), args.Get(2).([]policyinfo.PodEndpoint), args.Error(3)
}

func TestClusterNetworkPolicyEndpointsResolver_mergeClusterEndpointInfo(t *testing.T) {
	resolver := &clusterNetworkPolicyEndpointsResolver{
		logger: logr.Discard(),
	}

	tcpProtocol := corev1.ProtocolTCP
	port443 := int32(443)
	port80 := int32(80)

	tests := []struct {
		name     string
		input    []policyinfo.ClusterEndpointInfo
		expected int
	}{
		{
			name: "merge duplicate CIDR entries",
			input: []policyinfo.ClusterEndpointInfo{
				{CIDR: "10.0.0.0/8", Action: policyinfo.ClusterNetworkPolicyRuleActionAccept, Ports: []policyinfo.Port{{Protocol: &tcpProtocol, Port: &port443}}},
				{CIDR: "10.0.0.0/8", Action: policyinfo.ClusterNetworkPolicyRuleActionAccept, Ports: []policyinfo.Port{{Protocol: &tcpProtocol, Port: &port443}}},
				{CIDR: "0.0.0.0/0", Action: policyinfo.ClusterNetworkPolicyRuleActionDeny, Ports: []policyinfo.Port{}},
				{CIDR: "0.0.0.0/0", Action: policyinfo.ClusterNetworkPolicyRuleActionDeny, Ports: []policyinfo.Port{}},
			},
			expected: 2,
		},
		{
			name: "merge duplicate domain entries",
			input: []policyinfo.ClusterEndpointInfo{
				{DomainName: "example.com", Action: policyinfo.ClusterNetworkPolicyRuleActionAccept, Ports: []policyinfo.Port{{Protocol: &tcpProtocol, Port: &port443}}},
				{DomainName: "example.com", Action: policyinfo.ClusterNetworkPolicyRuleActionAccept, Ports: []policyinfo.Port{{Protocol: &tcpProtocol, Port: &port443}}},
				{DomainName: "google.com", Action: policyinfo.ClusterNetworkPolicyRuleActionPass, Ports: []policyinfo.Port{{Protocol: &tcpProtocol, Port: &port443}}},
			},
			expected: 2,
		},
		{
			name: "different ports should not merge",
			input: []policyinfo.ClusterEndpointInfo{
				{CIDR: "10.0.0.0/8", Action: policyinfo.ClusterNetworkPolicyRuleActionAccept, Ports: []policyinfo.Port{{Protocol: &tcpProtocol, Port: &port80}}},
				{CIDR: "10.0.0.0/8", Action: policyinfo.ClusterNetworkPolicyRuleActionAccept, Ports: []policyinfo.Port{{Protocol: &tcpProtocol, Port: &port443}}},
			},
			expected: 2,
		},
		{
			name: "different actions should not merge",
			input: []policyinfo.ClusterEndpointInfo{
				{CIDR: "10.0.0.0/8", Action: policyinfo.ClusterNetworkPolicyRuleActionAccept, Ports: []policyinfo.Port{{Protocol: &tcpProtocol, Port: &port443}}},
				{CIDR: "10.0.0.0/8", Action: policyinfo.ClusterNetworkPolicyRuleActionDeny, Ports: []policyinfo.Port{{Protocol: &tcpProtocol, Port: &port443}}},
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.mergeClusterEndpointInfo(tt.input)
			assert.Len(t, result, tt.expected)
		})
	}
}

func TestClusterNetworkPolicyEndpointsResolver_portsToString(t *testing.T) {
	resolver := &clusterNetworkPolicyEndpointsResolver{}

	tcpProtocol := corev1.ProtocolTCP
	port443 := int32(443)
	port80 := int32(80)

	tests := []struct {
		name     string
		ports    []policyinfo.Port
		expected string
	}{
		{
			name:     "empty ports",
			ports:    []policyinfo.Port{},
			expected: "all",
		},
		{
			name:     "single port",
			ports:    []policyinfo.Port{{Protocol: &tcpProtocol, Port: &port443}},
			expected: "TCP:443",
		},
		{
			name:     "multiple ports",
			ports:    []policyinfo.Port{{Protocol: &tcpProtocol, Port: &port80}, {Protocol: &tcpProtocol, Port: &port443}},
			expected: "TCP:80,TCP:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.portsToString(tt.ports)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClusterNetworkPolicyEndpointsResolver_convertSingleCNPEgressRuleToNP(t *testing.T) {
	resolver := &clusterNetworkPolicyEndpointsResolver{
		logger: logr.Discard(),
	}

	tests := []struct {
		name          string
		cnp           *policyinfo.ClusterNetworkPolicy
		rule          policyinfo.ClusterNetworkPolicyEgressRule
		namespace     string
		expectedPeers int
		expectedCIDRs []string
	}{
		{
			name: "multiple CIDRs in single peer",
			cnp: &policyinfo.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cnp"},
				Spec: policyinfo.ClusterNetworkPolicySpec{
					Subject: policyinfo.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
				},
			},
			rule: policyinfo.ClusterNetworkPolicyEgressRule{
				Name:   "multi-cidr-rule",
				Action: policyinfo.ClusterNetworkPolicyRuleActionAccept,
				To: []policyinfo.ClusterNetworkPolicyEgressPeer{
					{Networks: []policyinfo.CIDR{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}},
				},
			},
			namespace:     "default",
			expectedPeers: 3, // One peer per CIDR
			expectedCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		},
		{
			name: "mixed CIDR and namespace peers",
			cnp: &policyinfo.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cnp"},
				Spec: policyinfo.ClusterNetworkPolicySpec{
					Subject: policyinfo.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
				},
			},
			rule: policyinfo.ClusterNetworkPolicyEgressRule{
				Name:   "mixed-rule",
				Action: policyinfo.ClusterNetworkPolicyRuleActionAccept,
				To: []policyinfo.ClusterNetworkPolicyEgressPeer{
					{Networks: []policyinfo.CIDR{"10.0.0.0/8"}},
					{Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}},
				},
			},
			namespace:     "default",
			expectedPeers: 2, // One CIDR peer + one namespace peer
			expectedCIDRs: []string{"10.0.0.0/8"},
		},
		{
			name: "pod selector peer",
			cnp: &policyinfo.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cnp"},
				Spec: policyinfo.ClusterNetworkPolicySpec{
					Subject: policyinfo.ClusterNetworkPolicySubject{
						Pods: &policyinfo.NamespacedPod{
							NamespaceSelector: metav1.LabelSelector{},
							PodSelector:       metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
						},
					},
				},
			},
			rule: policyinfo.ClusterNetworkPolicyEgressRule{
				Name:   "pod-rule",
				Action: policyinfo.ClusterNetworkPolicyRuleActionAccept,
				To: []policyinfo.ClusterNetworkPolicyEgressPeer{
					{Pods: &policyinfo.NamespacedPod{
						NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tier": "backend"}},
						PodSelector:       metav1.LabelSelector{MatchLabels: map[string]string{"component": "database"}},
					}},
				},
			},
			namespace:     "default",
			expectedPeers: 1,
			expectedCIDRs: []string{}, // No CIDRs
		},
		{
			name: "domain names peer - should be ignored",
			cnp: &policyinfo.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cnp"},
				Spec: policyinfo.ClusterNetworkPolicySpec{
					Subject: policyinfo.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
				},
			},
			rule: policyinfo.ClusterNetworkPolicyEgressRule{
				Name:   "domain-rule",
				Action: policyinfo.ClusterNetworkPolicyRuleActionAccept,
				To: []policyinfo.ClusterNetworkPolicyEgressPeer{
					{DomainNames: []policyinfo.DomainName{"example.com", "google.com"}},
					{Networks: []policyinfo.CIDR{"10.0.0.0/8"}},
				},
			},
			namespace:     "default",
			expectedPeers: 1, // Only CIDR peer, domain names ignored
			expectedCIDRs: []string{"10.0.0.0/8"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			np := resolver.convertSingleCNPEgressRuleToNP(tt.cnp, tt.rule, tt.namespace)

			assert.NotNil(t, np)
			assert.Equal(t, tt.namespace, np.Namespace)
			assert.Len(t, np.Spec.Egress, 1, "should have exactly one egress rule")

			egressRule := np.Spec.Egress[0]
			assert.Len(t, egressRule.To, tt.expectedPeers, "peer count mismatch")

			// Check CIDRs
			foundCIDRs := []string{}
			for _, peer := range egressRule.To {
				if peer.IPBlock != nil {
					foundCIDRs = append(foundCIDRs, peer.IPBlock.CIDR)
				}
			}
			assert.ElementsMatch(t, tt.expectedCIDRs, foundCIDRs, "CIDR mismatch")

			// Verify pod selector is set correctly based on CNP subject
			if tt.cnp.Spec.Subject.Pods != nil {
				assert.Equal(t, tt.cnp.Spec.Subject.Pods.PodSelector, np.Spec.PodSelector)
			} else {
				// Should be empty selector for namespace-based subjects
				assert.Equal(t, metav1.LabelSelector{}, np.Spec.PodSelector)
			}
		})
	}
}

func TestClusterNetworkPolicyEndpointsResolver_resolveCNPEgressRules(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = networking.AddToScheme(scheme)
	_ = policyinfo.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	baseResolver := NewEndpointsResolver(fakeClient, logr.Discard())
	resolver := &clusterNetworkPolicyEndpointsResolver{
		k8sClient:    fakeClient,
		baseResolver: baseResolver,
		logger:       logr.Discard(),
	}

	tcpProtocol := corev1.ProtocolTCP
	port443 := int32(443)

	tests := []struct {
		name             string
		cnp              *policyinfo.ClusterNetworkPolicy
		targetNamespaces []string
		expectedCount    int
		expectedDomains  []string
		expectedCIDRs    []string
	}{
		{
			name: "CIDR egress rules",
			cnp: &policyinfo.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cnp"},
				Spec: policyinfo.ClusterNetworkPolicySpec{
					Subject: policyinfo.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Egress: []policyinfo.ClusterNetworkPolicyEgressRule{
						{
							Name:   "cidr-rule",
							Action: policyinfo.ClusterNetworkPolicyRuleActionAccept,
							To: []policyinfo.ClusterNetworkPolicyEgressPeer{
								{Networks: []policyinfo.CIDR{"10.0.0.0/8", "172.16.0.0/12"}},
							},
						},
					},
				},
			},
			targetNamespaces: []string{"ns1", "ns2"},
			expectedCount:    4, // 2 CIDRs × 2 namespaces
			expectedCIDRs:    []string{"10.0.0.0/8", "172.16.0.0/12"},
		},
		{
			name: "domain name egress rules",
			cnp: &policyinfo.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cnp"},
				Spec: policyinfo.ClusterNetworkPolicySpec{
					Subject: policyinfo.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Egress: []policyinfo.ClusterNetworkPolicyEgressRule{
						{
							Name:   "domain-accept",
							Action: policyinfo.ClusterNetworkPolicyRuleActionAccept,
							To: []policyinfo.ClusterNetworkPolicyEgressPeer{
								{DomainNames: []policyinfo.DomainName{"example.com"}},
							},
							Ports: &[]policyinfo.ClusterNetworkPolicyPort{
								{PortNumber: &policyinfo.CNPPort{Protocol: tcpProtocol, Port: port443}},
							},
						},
						{
							Name:   "domain-deny",
							Action: policyinfo.ClusterNetworkPolicyRuleActionDeny,
							To: []policyinfo.ClusterNetworkPolicyEgressPeer{
								{DomainNames: []policyinfo.DomainName{"blocked.com"}},
							},
						},
					},
				},
			},
			targetNamespaces: []string{"ns1"},
			expectedCount:    1, // Only Accept action, Deny ignored
			expectedDomains:  []string{"example.com"},
		},
		{
			name: "mixed CIDR and domain rules",
			cnp: &policyinfo.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cnp"},
				Spec: policyinfo.ClusterNetworkPolicySpec{
					Subject: policyinfo.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Egress: []policyinfo.ClusterNetworkPolicyEgressRule{
						{
							Name:   "mixed-rule",
							Action: policyinfo.ClusterNetworkPolicyRuleActionAccept,
							To: []policyinfo.ClusterNetworkPolicyEgressPeer{
								{Networks: []policyinfo.CIDR{"10.0.0.0/8"}},
								{DomainNames: []policyinfo.DomainName{"example.com"}},
							},
						},
					},
				},
			},
			targetNamespaces: []string{"ns1"},
			expectedCount:    2, // 1 CIDR + 1 domain
			expectedCIDRs:    []string{"10.0.0.0/8"},
			expectedDomains:  []string{"example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := resolver.resolveCNPEgressRules(context.Background(), tt.cnp, tt.targetNamespaces)

			assert.NoError(t, err)
			assert.Len(t, result, tt.expectedCount)

			// Check CIDRs
			foundCIDRs := []string{}
			for _, endpoint := range result {
				if endpoint.CIDR != "" {
					foundCIDRs = append(foundCIDRs, string(endpoint.CIDR))
				}
			}
			if len(tt.expectedCIDRs) > 0 {
				for _, expectedCIDR := range tt.expectedCIDRs {
					assert.Contains(t, foundCIDRs, expectedCIDR)
				}
			}

			// Check domains
			foundDomains := []string{}
			for _, endpoint := range result {
				if endpoint.DomainName != "" {
					foundDomains = append(foundDomains, string(endpoint.DomainName))
				}
			}
			assert.ElementsMatch(t, tt.expectedDomains, foundDomains)
		})
	}
}

func TestClusterNetworkPolicyEndpointsResolver_ResolveClusterNetworkPolicy(t *testing.T) {
	// Integration test with real resolver to catch duplication issues
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = networking.AddToScheme(scheme)
	_ = policyinfo.AddToScheme(scheme)

	// Create test namespaces
	ns1 := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns1"}}
	ns2 := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns2"}}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ns1, ns2).
		Build()

	// Create real base resolver
	baseResolver := NewEndpointsResolver(fakeClient, logr.Discard())

	// Create CNP resolver with real base resolver
	resolver := &clusterNetworkPolicyEndpointsResolver{
		k8sClient:    fakeClient,
		baseResolver: baseResolver,
		logger:       logr.Discard(),
	}

	tests := []struct {
		name                  string
		cnp                   *policyinfo.ClusterNetworkPolicy
		expectedIngressCount  int
		expectedEgressCount   int
		expectedPodCount      int
		expectedEgressDomains []string
	}{
		{
			name: "egress CIDR only - no duplicates",
			cnp: &policyinfo.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cnp-egress-cidr"},
				Spec: policyinfo.ClusterNetworkPolicySpec{
					Tier:     policyinfo.AdminTier,
					Priority: 100,
					Subject: policyinfo.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{}, // All namespaces
					},
					Egress: []policyinfo.ClusterNetworkPolicyEgressRule{
						{
							Name:   "allow-internal",
							Action: policyinfo.ClusterNetworkPolicyRuleActionAccept,
							To: []policyinfo.ClusterNetworkPolicyEgressPeer{
								{Networks: []policyinfo.CIDR{"10.0.0.0/8", "172.16.0.0/12"}},
							},
							Ports: &[]policyinfo.ClusterNetworkPolicyPort{
								{PortNumber: &policyinfo.CNPPort{Protocol: corev1.ProtocolTCP, Port: 443}},
							},
						},
						{
							Name:   "deny-external",
							Action: policyinfo.ClusterNetworkPolicyRuleActionDeny,
							To: []policyinfo.ClusterNetworkPolicyEgressPeer{
								{Networks: []policyinfo.CIDR{"0.0.0.0/0"}},
							},
						},
					},
				},
			},
			expectedIngressCount: 0,
			expectedEgressCount:  3, // 2 from first rule + 1 from second rule
			expectedPodCount:     0, // Optimized for egress-only
		},
		{
			name: "egress with FQDN Accept and Pass",
			cnp: &policyinfo.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cnp-fqdn"},
				Spec: policyinfo.ClusterNetworkPolicySpec{
					Tier:     policyinfo.AdminTier,
					Priority: 100,
					Subject: policyinfo.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Egress: []policyinfo.ClusterNetworkPolicyEgressRule{
						{
							Name:   "fqdn-accept-rule",
							Action: policyinfo.ClusterNetworkPolicyRuleActionAccept,
							To: []policyinfo.ClusterNetworkPolicyEgressPeer{
								{DomainNames: []policyinfo.DomainName{"example.com"}},
							},
						},
						{
							Name:   "fqdn-pass-rule",
							Action: policyinfo.ClusterNetworkPolicyRuleActionPass,
							To: []policyinfo.ClusterNetworkPolicyEgressPeer{
								{DomainNames: []policyinfo.DomainName{"google.com"}},
							},
						},
						{
							Name:   "fqdn-deny-rule",
							Action: policyinfo.ClusterNetworkPolicyRuleActionDeny,
							To: []policyinfo.ClusterNetworkPolicyEgressPeer{
								{DomainNames: []policyinfo.DomainName{"blocked.com"}},
							},
						},
					},
				},
			},
			expectedIngressCount:  0,
			expectedEgressCount:   2, // Only Accept and Pass, Deny should be ignored
			expectedPodCount:      0,
			expectedEgressDomains: []string{"example.com", "google.com"},
		},
		{
			name: "mixed CIDR and FQDN egress",
			cnp: &policyinfo.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cnp-mixed"},
				Spec: policyinfo.ClusterNetworkPolicySpec{
					Tier:     policyinfo.AdminTier,
					Priority: 100,
					Subject: policyinfo.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Egress: []policyinfo.ClusterNetworkPolicyEgressRule{
						{
							Name:   "cidr-rule",
							Action: policyinfo.ClusterNetworkPolicyRuleActionAccept,
							To: []policyinfo.ClusterNetworkPolicyEgressPeer{
								{Networks: []policyinfo.CIDR{"10.0.0.0/8"}},
							},
						},
						{
							Name:   "fqdn-rule",
							Action: policyinfo.ClusterNetworkPolicyRuleActionAccept,
							To: []policyinfo.ClusterNetworkPolicyEgressPeer{
								{DomainNames: []policyinfo.DomainName{"example.com"}},
							},
						},
					},
				},
			},
			expectedIngressCount:  0,
			expectedEgressCount:   2,
			expectedPodCount:      0,
			expectedEgressDomains: []string{"example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingressRules, egressRules, podEndpoints, err := resolver.ResolveClusterNetworkPolicy(context.Background(), tt.cnp)

			assert.NoError(t, err)
			assert.Len(t, ingressRules, tt.expectedIngressCount, "ingress rules count mismatch")
			assert.Len(t, egressRules, tt.expectedEgressCount, "egress rules count mismatch")
			assert.Len(t, podEndpoints, tt.expectedPodCount, "pod endpoints count mismatch")

			// Check egress domains
			if len(tt.expectedEgressDomains) > 0 {
				foundDomains := []string{}
				for _, rule := range egressRules {
					if rule.DomainName != "" {
						foundDomains = append(foundDomains, string(rule.DomainName))
					}
				}
				assert.ElementsMatch(t, tt.expectedEgressDomains, foundDomains, "egress domains mismatch")
			}

			// Verify no duplicates by checking unique CIDR+Action combinations
			seen := make(map[string]bool)
			for _, rule := range egressRules {
				var key string
				if rule.CIDR != "" {
					key = fmt.Sprintf("cidr:%s:%s", rule.CIDR, rule.Action)
				} else if rule.DomainName != "" {
					key = fmt.Sprintf("domain:%s:%s", rule.DomainName, rule.Action)
				}
				if key != "" {
					assert.False(t, seen[key], "found duplicate egress rule: %s", key)
					seen[key] = true
				}
			}
		})
	}
}
