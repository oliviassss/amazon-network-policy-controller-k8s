package metrics

import (
	"context"
	"time"

	"github.com/aws/amazon-network-policy-controller-k8s/api/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
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

	PolicyReconcileLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "network_policy_reconcile_duration_seconds",
			Help: "How long in seconds reconciling a policy takes",
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

	AdvancedNetworkPolicyEnabled = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "advanced_network_policy_enabled",
			Help: "Indicates if advanced network policies (ANP or CNP) are in use (1 if enabled, 0 if disabled)",
		},
	)
)

func init() {
	metrics.Registry.MustRegister(PolicyReconciliations, PolicyReconcileLatency, PolicyObjectCount, AdvancedNetworkPolicyEnabled)
}

func RecordPolicyReconcileLatency(policyType string, duration time.Duration) {
	PolicyReconcileLatency.WithLabelValues(policyType).Observe(duration.Seconds())
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
		return err
	}
	SetPolicyObjectCount("NetworkPolicy", float64(len(netpols.Items)))

	// Initialize ApplicationNetworkPolicy count
	var anps v1alpha1.ApplicationNetworkPolicyList
	if err := k8sClient.List(ctx, &anps, &client.ListOptions{}); err != nil {
		return err
	}
	SetPolicyObjectCount("ApplicationNetworkPolicy", float64(len(anps.Items)))

	// Initialize ClusterNetworkPolicy count
	var cnps v1alpha1.ClusterNetworkPolicyList
	if err := k8sClient.List(ctx, &cnps, &client.ListOptions{}); err != nil {
		return err
	}
	SetPolicyObjectCount("ClusterNetworkPolicy", float64(len(cnps.Items)))

	// Update advanced network policy enabled metric
	UpdateAdvancedNetworkPolicyEnabled()
	return nil
}

// Event-driven counter updates (no API calls)
func OnPolicyCreated(policyType string) {
	IncPolicyObjectCount(policyType)
	UpdateAdvancedNetworkPolicyEnabled()
}

func OnPolicyDeleted(policyType string) {
	DecPolicyObjectCount(policyType)
	UpdateAdvancedNetworkPolicyEnabled()
}

// UpdateAdvancedNetworkPolicyEnabled sets the metric to 1 if ANP or CNP policies exist, 0 otherwise
func UpdateAdvancedNetworkPolicyEnabled() {
	anpCount := PolicyObjectCount.WithLabelValues("ApplicationNetworkPolicy")
	cnpCount := PolicyObjectCount.WithLabelValues("ClusterNetworkPolicy")

	anpMetric := &dto.Metric{}
	cnpMetric := &dto.Metric{}

	anpCount.Write(anpMetric)
	cnpCount.Write(cnpMetric)

	if anpMetric.GetGauge().GetValue() > 0 || cnpMetric.GetGauge().GetValue() > 0 {
		AdvancedNetworkPolicyEnabled.Set(1)
	} else {
		AdvancedNetworkPolicyEnabled.Set(0)
	}
}
