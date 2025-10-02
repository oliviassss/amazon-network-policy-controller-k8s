package resolvers

import (
	"sync"

	policyinfo "github.com/aws/amazon-network-policy-controller-k8s/api/v1alpha1"
	"github.com/aws/amazon-network-policy-controller-k8s/pkg/k8s"
	"github.com/go-logr/logr"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type PolicyTracker interface {
	UpdatePolicy(policy *networking.NetworkPolicy)
	RemovePolicy(policy *networking.NetworkPolicy)
	UpdateGenericPolicy(obj client.Object)
	RemoveGenericPolicy(obj client.Object)
	GetPoliciesWithNamespaceReferences() sets.Set[types.NamespacedName]
	GetPoliciesWithEgressRules() sets.Set[types.NamespacedName]
}

func NewPolicyTracker(logger logr.Logger) PolicyTracker {
	return &defaultPolicyTracker{
		logger: logger,
	}
}

var _ PolicyTracker = (*defaultPolicyTracker)(nil)

type defaultPolicyTracker struct {
	logger              logr.Logger
	namespacedPolicies  sync.Map
	egressRulesPolicies sync.Map
}

// UpdateGenericPolicy handles both NetworkPolicy and ApplicationNetworkPolicy
func (t *defaultPolicyTracker) UpdateGenericPolicy(obj client.Object) {
	switch policy := obj.(type) {
	case *networking.NetworkPolicy:
		t.UpdatePolicy(policy)
	case *policyinfo.ApplicationNetworkPolicy:
		t.updateANP(policy)
	}
}

// RemoveGenericPolicy handles both NetworkPolicy and ApplicationNetworkPolicy
func (t *defaultPolicyTracker) RemoveGenericPolicy(obj client.Object) {
	switch policy := obj.(type) {
	case *networking.NetworkPolicy:
		t.RemovePolicy(policy)
	case *policyinfo.ApplicationNetworkPolicy:
		t.removeANP(policy)
	}
}

func (t *defaultPolicyTracker) updateANP(policy *policyinfo.ApplicationNetworkPolicy) {
	if t.containsANPNamespaceReference(policy) {
		t.logger.V(1).Info("ANP contains ns references", "policy", k8s.NamespacedName(policy))
		t.namespacedPolicies.Store(k8s.NamespacedName(policy), true)
	} else {
		t.logger.V(1).Info("ANP no ns references, remove tracking", "policy", k8s.NamespacedName(policy))
		t.namespacedPolicies.Delete(k8s.NamespacedName(policy))
	}
	if t.containsANPEgressRules(policy) {
		t.logger.V(1).Info("ANP contains egress rules", "policy", k8s.NamespacedName(policy))
		t.egressRulesPolicies.Store(k8s.NamespacedName(policy), true)
	} else {
		t.logger.V(1).Info("ANP no egress rules, remove tracking", "policy", k8s.NamespacedName(policy))
		t.egressRulesPolicies.Delete(k8s.NamespacedName(policy))
	}
}

func (t *defaultPolicyTracker) removeANP(policy *policyinfo.ApplicationNetworkPolicy) {
	t.logger.V(1).Info("remove ANP from tracking", "policy", k8s.NamespacedName(policy))
	t.namespacedPolicies.Delete(k8s.NamespacedName(policy))
	t.egressRulesPolicies.Delete(k8s.NamespacedName(policy))
}

func (t *defaultPolicyTracker) containsANPNamespaceReference(policy *policyinfo.ApplicationNetworkPolicy) bool {
	for _, ingRule := range policy.Spec.Ingress {
		for _, peer := range ingRule.From {
			if peer.NamespaceSelector != nil {
				return true
			}
		}
	}
	for _, egrRule := range policy.Spec.Egress {
		for _, peer := range egrRule.To {
			if peer.NamespaceSelector != nil {
				return true
			}
		}
	}
	return false
}

func (t *defaultPolicyTracker) containsANPEgressRules(policy *policyinfo.ApplicationNetworkPolicy) bool {
	return len(policy.Spec.Egress) > 0
}

// UpdatePolicy updates the policy tracker with the given policy
func (t *defaultPolicyTracker) UpdatePolicy(policy *networking.NetworkPolicy) {
	if t.containsNamespaceReference(policy) {
		t.logger.V(1).Info("policy contains ns references", "policy", k8s.NamespacedName(policy))
		t.namespacedPolicies.Store(k8s.NamespacedName(policy), true)
	} else {
		t.logger.V(1).Info("no ns references, remove tracking", "policy", k8s.NamespacedName(policy))
		t.namespacedPolicies.Delete(k8s.NamespacedName(policy))
	}
	if t.containsEgressRules(policy) {
		t.logger.V(1).Info("policy contains egress rules", "policy", k8s.NamespacedName(policy))
		t.egressRulesPolicies.Store(k8s.NamespacedName(policy), true)
	} else {
		t.logger.V(1).Info("no egress rules, remove tracking", "policy", k8s.NamespacedName(policy))
		t.egressRulesPolicies.Delete(k8s.NamespacedName(policy))
	}
}

// RemovePolicy removes the given policy from the policy tracker during deletion
func (t *defaultPolicyTracker) RemovePolicy(policy *networking.NetworkPolicy) {
	t.logger.V(1).Info("remove from tracking", "policy", k8s.NamespacedName(policy))
	t.namespacedPolicies.Delete(k8s.NamespacedName(policy))
	t.egressRulesPolicies.Delete(k8s.NamespacedName(policy))
}

// GetPoliciesWithNamespaceReferences returns the set of policies that have namespace references in the ingress/egress rules
func (t *defaultPolicyTracker) GetPoliciesWithNamespaceReferences() sets.Set[types.NamespacedName] {
	policies := sets.Set[types.NamespacedName]{}
	t.namespacedPolicies.Range(func(k, _ interface{}) bool {
		policies.Insert(k.(types.NamespacedName))
		return true
	})
	return policies
}

// GetPoliciesWithEgressRules returns the set of policies that have egress rules
func (t *defaultPolicyTracker) GetPoliciesWithEgressRules() sets.Set[types.NamespacedName] {
	policies := sets.Set[types.NamespacedName]{}
	t.egressRulesPolicies.Range(func(k, _ interface{}) bool {
		policies.Insert(k.(types.NamespacedName))
		return true
	})
	return policies
}

func (t *defaultPolicyTracker) containsNamespaceReference(policy *networking.NetworkPolicy) bool {
	for _, ingRule := range policy.Spec.Ingress {
		for _, peer := range ingRule.From {
			if peer.NamespaceSelector != nil {
				return true
			}
		}
	}
	for _, egrRule := range policy.Spec.Egress {
		for _, peer := range egrRule.To {
			if peer.NamespaceSelector != nil {
				return true
			}
		}
	}
	return false
}

func (t *defaultPolicyTracker) containsEgressRules(policy *networking.NetworkPolicy) bool {
	return len(policy.Spec.Egress) > 0
}
