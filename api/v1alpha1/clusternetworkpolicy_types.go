/*
Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterNetworkPolicySpec defines the desired state of ClusterNetworkPolicy
type ClusterNetworkPolicySpec struct {
	// Tier specifies the policy tier (Admin, Baseline)
	// +kubebuilder:validation:Enum={"Admin", "Baseline"}
	Tier Tier `json:"tier"`

	// Priority within the tier (0-1000, lower = higher precedence)
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000
	Priority int32 `json:"priority"`

	// Subject defines which pods this policy applies to
	Subject ClusterNetworkPolicySubject `json:"subject"`

	// Ingress rules
	// +optional
	// +kubebuilder:validation:MaxItems=100
	Ingress []ClusterNetworkPolicyIngressRule `json:"ingress,omitempty"`

	// Egress rules
	// +optional
	// +kubebuilder:validation:MaxItems=100
	Egress []ClusterNetworkPolicyEgressRule `json:"egress,omitempty"`
}

// +kubebuilder:validation:Enum={"Admin", "Baseline"}
type Tier string

const (
	AdminTier    Tier = "Admin"
	BaselineTier Tier = "Baseline"
)

// ClusterNetworkPolicySubject defines what resources the policy applies to.
// Exactly one field must be set.
// +kubebuilder:validation:MaxProperties=1
// +kubebuilder:validation:MinProperties=1
type ClusterNetworkPolicySubject struct {
	// Namespaces is used to select pods via namespace selectors.
	// +optional
	Namespaces *metav1.LabelSelector `json:"namespaces,omitempty"`
	// Pods is used to select pods via namespace AND pod selectors.
	// +optional
	Pods *NamespacedPod `json:"pods,omitempty"`
}

// NamespacedPod allows the user to select a given set of pod(s) in selected namespace(s).
type NamespacedPod struct {
	// NamespaceSelector follows standard label selector semantics; if empty,
	// it selects all Namespaces.
	NamespaceSelector metav1.LabelSelector `json:"namespaceSelector"`

	// PodSelector is used to explicitly select pods within a namespace;
	// if empty, it selects all Pods.
	PodSelector metav1.LabelSelector `json:"podSelector"`
}

type ClusterNetworkPolicyIngressRule struct {
	// Name is an identifier for this rule, that may be no more than
	// 100 characters in length. This field should be used by the implementation
	// to help improve observability, readability and error-reporting
	// for any applied AdminNetworkPolicies.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=100
	Name string `json:"name,omitempty"`

	// Action specifies the effect this rule will have on matching traffic.
	Action ClusterNetworkPolicyRuleAction `json:"action"`

	// From is the list of sources whose traffic this rule applies to.
	// If any element matches the source of incoming
	// traffic then the specified action is applied.
	// This field must be defined and contain at least one item.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	From []ClusterNetworkPolicyIngressPeer `json:"from"`

	// Ports allows for matching traffic based on port and protocols.
	// This field is a list of ports which should be matched on
	// the pods selected for this policy i.e the subject of the policy.
	// So it matches on the destination port for the ingress traffic.
	// If Ports is not set then the rule does not filter traffic via port.
	//
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	Ports *[]ClusterNetworkPolicyPort `json:"ports,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="!(self.action == 'Deny' && self.to.exists(peer, has(peer.domainNames)))",message="domainNames peer cannot be used with Deny action, only Accept and Pass actions are supported for domainNames"
type ClusterNetworkPolicyEgressRule struct {
	// Name is an identifier for this rule, that may be no more than
	// 100 characters in length. This field should be used by the implementation
	// to help improve observability, readability and error-reporting
	// for any applied AdminNetworkPolicies.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=100
	Name string `json:"name,omitempty"`

	// Action specifies the effect this rule will have on matching traffic.
	Action ClusterNetworkPolicyRuleAction `json:"action"`

	// To is the List of destinations whose traffic this rule applies to.
	// If any element matches the destination of outgoing
	// traffic then the specified action is applied.
	// This field must be defined and contain at least one item.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	To []ClusterNetworkPolicyEgressPeer `json:"to"`

	// Ports allows for matching traffic based on port and protocols.
	// This field is a list of destination ports for the outgoing egress traffic.
	// If Ports is not set then the rule does not filter traffic via port.
	//
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	Ports *[]ClusterNetworkPolicyPort `json:"ports,omitempty"`
}

// +kubebuilder:validation:Enum={"Accept", "Deny", "Pass"}
type ClusterNetworkPolicyRuleAction string

const (
	ClusterNetworkPolicyRuleActionAccept ClusterNetworkPolicyRuleAction = "Accept"
	ClusterNetworkPolicyRuleActionDeny   ClusterNetworkPolicyRuleAction = "Deny"
	ClusterNetworkPolicyRuleActionPass   ClusterNetworkPolicyRuleAction = "Pass"
)

// ClusterNetworkPolicyIngressPeer defines a peer to allow traffic from.
//
// Exactly one of the fields must be set for a given peer and this is enforced
// by the validation rules on the CRD. If an implementation sees no fields are
// set then it can infer that the deployed CRD is of an incompatible version
// with an unknown field. In that case it should fail closed.
//
// +kubebuilder:validation:MaxProperties=1
// +kubebuilder:validation:MinProperties=1
type ClusterNetworkPolicyIngressPeer struct {
	// Namespaces defines a way to select all pods within a set of Namespaces.
	// Note that host-networked pods are not included in this type of peer.
	//
	// +optional
	Namespaces *metav1.LabelSelector `json:"namespaces,omitempty"`
	// Pods defines a way to select a set of pods in
	// a set of namespaces. Note that host-networked pods
	// are not included in this type of peer.
	//
	// +optional
	Pods *NamespacedPod `json:"pods,omitempty"`
}

// ClusterNetworkPolicyEgressPeer defines a peer to allow traffic to.
//
// Exactly one of the fields must be set for a given peer and this is enforced
// by the validation rules on the CRD. If an implementation sees no fields are
// set then it can infer that the deployed CRD is of an incompatible version
// with an unknown field. In that case it should fail closed.
//
// +kubebuilder:validation:MaxProperties=1
// +kubebuilder:validation:MinProperties=1
type ClusterNetworkPolicyEgressPeer struct {
	// Namespaces defines a way to select all pods within a set of Namespaces.
	// Note that host-networked pods are not included in this type of peer.
	//
	// +optional
	Namespaces *metav1.LabelSelector `json:"namespaces,omitempty"`
	// Pods defines a way to select a set of pods in
	// a set of namespaces. Note that host-networked pods
	// are not included in this type of peer.
	//
	// +optional
	Pods *NamespacedPod `json:"pods,omitempty"`
	// Networks defines a way to select peers via CIDR blocks.
	//
	// +optional
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=25
	Networks []CIDR `json:"networks,omitempty"`

	// DomainNames provides a way to specify domain names as peers.
	// DomainNames support Accept and Pass actions (our extension from upstream)
	// Upstream CNP only supports Accept for domainNames, we add Pass support
	//
	// +optional
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=25
	DomainNames []DomainName `json:"domainNames,omitempty"`
}

// CIDR is an IP address range in CIDR notation
// (for example, "10.0.0.0/8" or "fd00::/8").
// +kubebuilder:validation:MaxLength=43
type CIDR string

type ClusterNetworkPolicyPort struct {
	// +optional
	PortNumber *CNPPort `json:"portNumber,omitempty"`
	// +optional
	PortRange *CNPPortRange `json:"portRange,omitempty"`
	// +optional
	NamedPort *string `json:"namedPort,omitempty"`
}

type CNPPort struct {
	// Protocol is the network protocol (TCP, UDP, or SCTP) which traffic must
	// match. If not specified, this field defaults to TCP.
	// +kubebuilder:default=TCP
	Protocol corev1.Protocol `json:"protocol"`

	// Port defines a network port value.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// CNPPortRange defines an inclusive range of ports from the assigned
// Start value to End value.
// +kubebuilder:validation:XValidation:rule="self.start < self.end", message="Start port must be less than End port"
type CNPPortRange struct {
	// Protocol is the network protocol (TCP, UDP, or SCTP) which traffic must
	// match. If not specified, this field defaults to TCP.
	// +kubebuilder:default=TCP
	Protocol corev1.Protocol `json:"protocol,omitempty"`

	// Start defines a network port that is the start of a port range, the Start
	// value must be less than End.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Start int32 `json:"start"`

	// End defines a network port that is the end of a port range, the End value
	// must be greater than Start.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	End int32 `json:"end"`
}

// ClusterNetworkPolicyStatus defines the observed state of ClusterNetworkPolicy
type ClusterNetworkPolicyStatus struct {
	// Conditions represent the latest available observations of the ClusterNetworkPolicy's current state.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:shortName=cnp,scope=Cluster

// ClusterNetworkPolicy is the Schema for the clusternetworkpolicies API
type ClusterNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterNetworkPolicySpec   `json:"spec,omitempty"`
	Status ClusterNetworkPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ClusterNetworkPolicyList contains a list of ClusterNetworkPolicy
type ClusterNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterNetworkPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterNetworkPolicy{}, &ClusterNetworkPolicyList{})
}
