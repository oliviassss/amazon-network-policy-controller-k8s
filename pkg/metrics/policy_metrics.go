package metrics

import (
	"context"
	"time"

	"github.com/aws/amazon-network-policy-controller-k8s/api/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	networking "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	PolicyReconciliations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "network_policy_reconciliations_total",
			Help: "Total number of policy reconciliations by type and result",
		},
		[]string{"policy_type", "result"},
	)

	PolicyWorkDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "network_policy_workqueue_work_duration_seconds",
			Help: "How long in seconds processing a policy from workqueue takes",
		},
		[]string{"policy_type"},
	)

	PolicyQueueDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "network_policy_workqueue_queue_duration_seconds",
			Help: "How long in seconds a policy stays in workqueue before being processed",
		},
		[]string{"policy_type"},
	)

	PolicyObjectCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "network_policy_objects_total",
			Help: "Total number of policy objects in the cluster by type",
		},
		[]string{"policy_type"},
	)
)

func init() {
	metrics.Registry.MustRegister(PolicyReconciliations, PolicyWorkDuration, PolicyQueueDuration, PolicyObjectCount)
}

func RecordWorkDuration(policyType string, duration time.Duration) {
	PolicyWorkDuration.WithLabelValues(policyType).Observe(duration.Seconds())
}

func RecordQueueDuration(policyType string, duration time.Duration) {
	PolicyQueueDuration.WithLabelValues(policyType).Observe(duration.Seconds())
}

func SetPolicyObjectCount(policyType string, count float64) {
	PolicyObjectCount.WithLabelValues(policyType).Set(count)
}

func IncPolicyObjectCount(policyType string) {
	PolicyObjectCount.WithLabelValues(policyType).Inc()
}

func DecPolicyObjectCount(policyType string) {
	PolicyObjectCount.WithLabelValues(policyType).Dec()
}

// InitializePolicyObjectCounts initializes counters by listing existing policies (called once at startup)
func InitializePolicyObjectCounts(ctx context.Context, k8sClient client.Client) error {
	// Initialize NetworkPolicy count
	var netpols networking.NetworkPolicyList
	if err := k8sClient.List(ctx, &netpols, &client.ListOptions{}); err != nil {
		SetPolicyObjectCount("NetworkPolicy", 0)
	} else {
		count := float64(len(netpols.Items))
		SetPolicyObjectCount("NetworkPolicy", count)
	}

	// Initialize ApplicationNetworkPolicy count
	var anps v1alpha1.ApplicationNetworkPolicyList
	if err := k8sClient.List(ctx, &anps, &client.ListOptions{}); err != nil {
		SetPolicyObjectCount("ApplicationNetworkPolicy", 0)
	} else {
		count := float64(len(anps.Items))
		SetPolicyObjectCount("ApplicationNetworkPolicy", count)
	}

	// Initialize ClusterNetworkPolicy count
	var cnps v1alpha1.ClusterNetworkPolicyList
	if err := k8sClient.List(ctx, &cnps, &client.ListOptions{}); err != nil {
		SetPolicyObjectCount("ClusterNetworkPolicy", 0)
	} else {
		count := float64(len(cnps.Items))
		SetPolicyObjectCount("ClusterNetworkPolicy", count)
	}

	return nil
}

// Event-driven counter updates (no API calls)
func OnPolicyCreated(policyType string) {
	IncPolicyObjectCount(policyType)
}

func OnPolicyDeleted(policyType string) {
	DecPolicyObjectCount(policyType)
}
