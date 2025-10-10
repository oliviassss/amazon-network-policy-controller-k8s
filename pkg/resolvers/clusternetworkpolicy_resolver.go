package resolvers

import (
	"context"
	"fmt"
	"strings"

	policyinfo "github.com/aws/amazon-network-policy-controller-k8s/api/v1alpha1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ClusterNetworkPolicyEndpointsResolver interface {
	// ResolveClusterNetworkPolicy returns the resolved endpoints for the given ClusterNetworkPolicy
	ResolveClusterNetworkPolicy(ctx context.Context, cnp *policyinfo.ClusterNetworkPolicy) ([]policyinfo.ClusterEndpointInfo, []policyinfo.ClusterEndpointInfo, []policyinfo.PodEndpoint, error)
}

// NewClusterNetworkPolicyEndpointsResolver constructs a new clusterNetworkPolicyEndpointsResolver
func NewClusterNetworkPolicyEndpointsResolver(k8sClient client.Client, logger logr.Logger) *clusterNetworkPolicyEndpointsResolver {
	baseResolver := NewEndpointsResolver(k8sClient, logger.WithName("base-resolver"))
	return &clusterNetworkPolicyEndpointsResolver{
		k8sClient:    k8sClient,
		baseResolver: baseResolver,
		logger:       logger,
	}
}

var _ ClusterNetworkPolicyEndpointsResolver = (*clusterNetworkPolicyEndpointsResolver)(nil)

type clusterNetworkPolicyEndpointsResolver struct {
	k8sClient    client.Client
	baseResolver EndpointsResolver
	logger       logr.Logger
}

func (r *clusterNetworkPolicyEndpointsResolver) ResolveClusterNetworkPolicy(ctx context.Context, cnp *policyinfo.ClusterNetworkPolicy) ([]policyinfo.ClusterEndpointInfo, []policyinfo.ClusterEndpointInfo, []policyinfo.PodEndpoint, error) {
	// 1. Resolve target namespaces based on cnp.Spec.Subject
	targetNamespaces, err := r.resolveTargetNamespaces(ctx, cnp.Spec.Subject)
	if err != nil {
		return nil, nil, nil, err
	}

	var allPodEndpoints []policyinfo.PodEndpoint
	var allIngressRules []policyinfo.ClusterEndpointInfo
	var allEgressRules []policyinfo.ClusterEndpointInfo

	// 2. Optimize for egress-only policies with namespaces:{}
	if cnp.Spec.Subject.Namespaces != nil && len(cnp.Spec.Ingress) == 0 {
		// Egress-only with namespaces:{} - skip expensive pod enumeration
		allPodEndpoints = []policyinfo.PodEndpoint{}
	} else {
		// 2. Reuse existing NP resolver for each target namespace (for ingress rules)
		for _, ns := range targetNamespaces {
			// Create a temporary NP-like structure to reuse existing resolver
			tempNP := r.convertCNPToNetworkPolicy(cnp, ns)

			// Reuse existing NP resolver for ingress and pod selection
			ingressRules, _, podEndpoints, err := r.baseResolver.Resolve(ctx, tempNP)
			if err != nil {
				return nil, nil, nil, err
			}

			// Convert NP EndpointInfo to CNP ClusterEndpointInfo with actions
			for i, rule := range ingressRules {
				if i < len(cnp.Spec.Ingress) {
					allIngressRules = append(allIngressRules, policyinfo.ClusterEndpointInfo{
						CIDR:   rule.CIDR,
						Ports:  rule.Ports,
						Action: cnp.Spec.Ingress[i].Action,
					})
				}
			}

			allPodEndpoints = append(allPodEndpoints, podEndpoints...)
		}
	}

	// 3. Handle CNP-specific egress rules (process once, not per namespace)
	egressRules, err := r.resolveCNPEgressRules(ctx, cnp, targetNamespaces)
	if err != nil {
		return nil, nil, nil, err
	}
	allEgressRules = r.mergeClusterEndpointInfo(egressRules)

	r.logger.Info("Resolved ClusterNetworkPolicy endpoints", "policy", cnp.Name, "ingress", len(allIngressRules), "egress", len(allEgressRules), "pod selector endpoints", len(allPodEndpoints))

	return allIngressRules, allEgressRules, allPodEndpoints, nil
}

func (r *clusterNetworkPolicyEndpointsResolver) mergeClusterEndpointInfo(rules []policyinfo.ClusterEndpointInfo) []policyinfo.ClusterEndpointInfo {
	seen := make(map[string]bool)
	var result []policyinfo.ClusterEndpointInfo

	for _, rule := range rules {
		var key string
		if rule.CIDR != "" {
			key = fmt.Sprintf("cidr:%s:%s:%s", rule.CIDR, rule.Action, r.portsToString(rule.Ports))
		} else if rule.DomainName != "" {
			key = fmt.Sprintf("domain:%s:%s:%s", rule.DomainName, rule.Action, r.portsToString(rule.Ports))
		} else {
			// Skip invalid entries
			continue
		}

		if !seen[key] {
			seen[key] = true
			result = append(result, rule)
		}
	}
	return result
}

func (r *clusterNetworkPolicyEndpointsResolver) portsToString(ports []policyinfo.Port) string {
	if len(ports) == 0 {
		return "all"
	}
	var portStrs []string
	for _, port := range ports {
		protocol := "TCP"
		if port.Protocol != nil {
			protocol = string(*port.Protocol)
		}
		portNum := "any"
		if port.Port != nil {
			portNum = fmt.Sprintf("%d", *port.Port)
		}
		portStrs = append(portStrs, fmt.Sprintf("%s:%s", protocol, portNum))
	}
	return strings.Join(portStrs, ",")
}

func (r *clusterNetworkPolicyEndpointsResolver) resolveTargetNamespaces(ctx context.Context, subject policyinfo.ClusterNetworkPolicySubject) ([]string, error) {
	if subject.Namespaces != nil {
		// Handle namespace selector
		return r.resolveNamespacesBySelector(ctx, *subject.Namespaces)
	} else if subject.Pods != nil {
		// Handle pods selector - get namespaces from NamespaceSelector
		return r.resolveNamespacesBySelector(ctx, subject.Pods.NamespaceSelector)
	}
	return nil, nil
}

func (r *clusterNetworkPolicyEndpointsResolver) resolveNamespacesBySelector(ctx context.Context, nsSelector metav1.LabelSelector) ([]string, error) {
	// Empty selector {} means all namespaces
	if len(nsSelector.MatchLabels) == 0 && len(nsSelector.MatchExpressions) == 0 {
		namespaceList := &corev1.NamespaceList{}
		if err := r.k8sClient.List(ctx, namespaceList); err != nil {
			return nil, err
		}

		var namespaces []string
		for _, ns := range namespaceList.Items {
			namespaces = append(namespaces, ns.Name)
		}
		return namespaces, nil
	}

	// Non-empty selector - use label matching
	namespaceList := &corev1.NamespaceList{}
	selector, err := metav1.LabelSelectorAsSelector(&nsSelector)
	if err != nil {
		return nil, err
	}

	if err := r.k8sClient.List(ctx, namespaceList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, err
	}

	var namespaces []string
	for _, ns := range namespaceList.Items {
		namespaces = append(namespaces, ns.Name)
	}
	return namespaces, nil
}

func (r *clusterNetworkPolicyEndpointsResolver) convertCNPToNetworkPolicy(cnp *policyinfo.ClusterNetworkPolicy, namespace string) *networking.NetworkPolicy {
	// Convert CNP ingress rules to NP ingress rules
	var ingressRules []networking.NetworkPolicyIngressRule
	for _, rule := range cnp.Spec.Ingress {
		npRule := networking.NetworkPolicyIngressRule{
			From: r.convertCNPIngressPeersToNPPeers(rule.From),
		}
		// Convert ports if present
		if rule.Ports != nil {
			npRule.Ports = r.convertCNPPortsToNPPorts(*rule.Ports)
		}
		ingressRules = append(ingressRules, npRule)
	}

	// Determine pod selector based on CNP subject
	var podSelector metav1.LabelSelector
	if cnp.Spec.Subject.Pods != nil {
		podSelector = cnp.Spec.Subject.Pods.PodSelector
	}
	// If subject.Namespaces is used, select all pods (empty selector)

	return &networking.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cnp.Name,
			Namespace: namespace,
		},
		Spec: networking.NetworkPolicySpec{
			PodSelector: podSelector,
			Ingress:     ingressRules,
			// Egress will be handled separately for domainNames
		},
	}
}

func (r *clusterNetworkPolicyEndpointsResolver) convertCNPIngressPeersToNPPeers(cnpPeers []policyinfo.ClusterNetworkPolicyIngressPeer) []networking.NetworkPolicyPeer {
	var npPeers []networking.NetworkPolicyPeer
	for _, peer := range cnpPeers {
		npPeer := networking.NetworkPolicyPeer{}
		if peer.Namespaces != nil {
			npPeer.NamespaceSelector = peer.Namespaces
		}
		if peer.Pods != nil {
			npPeer.NamespaceSelector = &peer.Pods.NamespaceSelector
			npPeer.PodSelector = &peer.Pods.PodSelector
		}
		npPeers = append(npPeers, npPeer)
	}
	return npPeers
}

func (r *clusterNetworkPolicyEndpointsResolver) convertCNPPortsToNPPorts(cnpPorts []policyinfo.ClusterNetworkPolicyPort) []networking.NetworkPolicyPort {
	var npPorts []networking.NetworkPolicyPort
	for _, cnpPort := range cnpPorts {
		if cnpPort.PortNumber != nil {
			npPorts = append(npPorts, networking.NetworkPolicyPort{
				Protocol: &cnpPort.PortNumber.Protocol,
				Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: cnpPort.PortNumber.Port},
			})
		}
		if cnpPort.PortRange != nil {
			// Handle port range - create multiple ports or use endPort if supported
			npPorts = append(npPorts, networking.NetworkPolicyPort{
				Protocol: &cnpPort.PortRange.Protocol,
				Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: cnpPort.PortRange.Start},
				EndPort:  &cnpPort.PortRange.End,
			})
		}
		if cnpPort.NamedPort != nil {
			npPorts = append(npPorts, networking.NetworkPolicyPort{
				Port: &intstr.IntOrString{Type: intstr.String, StrVal: *cnpPort.NamedPort},
			})
		}
	}
	return npPorts
}

func (r *clusterNetworkPolicyEndpointsResolver) convertCNPPortsToEndpointPorts(cnpPorts *[]policyinfo.ClusterNetworkPolicyPort) []policyinfo.Port {
	if cnpPorts == nil {
		return nil
	}

	var ports []policyinfo.Port
	for _, cnpPort := range *cnpPorts {
		if cnpPort.PortNumber != nil {
			ports = append(ports, policyinfo.Port{
				Protocol: &cnpPort.PortNumber.Protocol,
				Port:     &cnpPort.PortNumber.Port,
			})
		}
		if cnpPort.PortRange != nil {
			ports = append(ports, policyinfo.Port{
				Protocol: &cnpPort.PortRange.Protocol,
				Port:     &cnpPort.PortRange.Start,
				EndPort:  &cnpPort.PortRange.End,
			})
		}
	}
	return ports
}

func (r *clusterNetworkPolicyEndpointsResolver) resolveCNPEgressRules(ctx context.Context, cnp *policyinfo.ClusterNetworkPolicy, targetNamespaces []string) ([]policyinfo.ClusterEndpointInfo, error) {
	var endpointInfos []policyinfo.ClusterEndpointInfo

	for _, rule := range cnp.Spec.Egress {
		// Check if this specific rule has CIDR/namespace/pod peers
		hasCIDRPeers := false
		for _, peer := range rule.To {
			if len(peer.Networks) > 0 || peer.Namespaces != nil || peer.Pods != nil {
				hasCIDRPeers = true
				break
			}
		}

		// Handle CIDR/namespace/pod peers using NP resolver
		if hasCIDRPeers {
			for _, ns := range targetNamespaces {
				// Create NP with only this specific rule
				tempNP := r.convertSingleCNPEgressRuleToNP(cnp, rule, ns)
				_, cidrEgressEndpoints, _, err := r.baseResolver.Resolve(ctx, tempNP)
				if err != nil {
					return nil, err
				}

				// Convert with correct action
				for _, endpoint := range cidrEgressEndpoints {
					endpointInfos = append(endpointInfos, policyinfo.ClusterEndpointInfo{
						CIDR:   endpoint.CIDR,
						Ports:  endpoint.Ports,
						Action: rule.Action,
					})
				}
			}
		}

		// Handle domainNames for this rule
		for _, peer := range rule.To {
			if len(peer.DomainNames) > 0 {
				for _, domain := range peer.DomainNames {
					if rule.Action == policyinfo.ClusterNetworkPolicyRuleActionAccept ||
						rule.Action == policyinfo.ClusterNetworkPolicyRuleActionPass {
						endpointInfos = append(endpointInfos, policyinfo.ClusterEndpointInfo{
							DomainName: domain,
							Action:     rule.Action,
							Ports:      r.convertCNPPortsToEndpointPorts(rule.Ports),
						})
					}
					// Ignore Deny action for domainNames as it's not supported
				}
			}
		}
	}

	return endpointInfos, nil
}

func (r *clusterNetworkPolicyEndpointsResolver) convertSingleCNPEgressRuleToNP(cnp *policyinfo.ClusterNetworkPolicy, rule policyinfo.ClusterNetworkPolicyEgressRule, namespace string) *networking.NetworkPolicy {
	// Convert only CIDR/namespace/pod peers, skip domainNames
	var npPeers []networking.NetworkPolicyPeer
	for _, peer := range rule.To {
		if len(peer.Networks) > 0 {
			// Create separate NP peer for each CIDR
			for _, cidr := range peer.Networks {
				npPeer := networking.NetworkPolicyPeer{
					IPBlock: &networking.IPBlock{
						CIDR: string(cidr),
					},
				}
				npPeers = append(npPeers, npPeer)
			}
		}
		if peer.Namespaces != nil || peer.Pods != nil {
			npPeer := networking.NetworkPolicyPeer{}
			if peer.Namespaces != nil {
				npPeer.NamespaceSelector = peer.Namespaces
			}
			if peer.Pods != nil {
				npPeer.NamespaceSelector = &peer.Pods.NamespaceSelector
				npPeer.PodSelector = &peer.Pods.PodSelector
			}
			npPeers = append(npPeers, npPeer)
		}
	}

	egressRule := networking.NetworkPolicyEgressRule{
		To: npPeers,
	}
	if rule.Ports != nil {
		egressRule.Ports = r.convertCNPPortsToNPPorts(*rule.Ports)
	}

	// Determine pod selector based on CNP subject
	var podSelector metav1.LabelSelector
	if cnp.Spec.Subject.Pods != nil {
		podSelector = cnp.Spec.Subject.Pods.PodSelector
	}

	return &networking.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cnp.Name,
			Namespace: namespace,
		},
		Spec: networking.NetworkPolicySpec{
			PodSelector: podSelector,
			Egress:      []networking.NetworkPolicyEgressRule{egressRule},
		},
	}
}
