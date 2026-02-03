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

package controllers

import (
	"context"
	"fmt"
	"strings"
	"time"

	policyinfo "github.com/aws/amazon-network-policy-controller-k8s/api/v1alpha1"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/aws/amazon-network-policy-controller-k8s/internal/eventhandlers"
	"github.com/aws/amazon-network-policy-controller-k8s/pkg/config"
	"github.com/aws/amazon-network-policy-controller-k8s/pkg/k8s"
	"github.com/aws/amazon-network-policy-controller-k8s/pkg/metrics"
	"github.com/aws/amazon-network-policy-controller-k8s/pkg/policyendpoints"
	"github.com/aws/amazon-network-policy-controller-k8s/pkg/resolvers"
)

const (
	controllerName      = "policy"
	policyFinalizerName = "networking.k8s.aws/resources"
	anpFinalizerName    = "networking.k8s.aws/anp-resources"
	cnpFinalizerName    = "networking.k8s.aws/cnp-resources"
)

func NewPolicyReconciler(k8sClient client.Client, policyEndpointsManager policyendpoints.PolicyEndpointsManager,
	controllerConfig config.ControllerConfig, finalizerManager k8s.FinalizerManager, logger logr.Logger) *policyReconciler {
	policyTracker := resolvers.NewPolicyTracker(logger.WithName("policy-tracker"))
	policyResolver := resolvers.NewPolicyReferenceResolver(k8sClient, policyTracker, logger.WithName("policy-resolver"))
	return &policyReconciler{
		k8sClient:                    k8sClient,
		policyResolver:               policyResolver,
		policyTracker:                policyTracker,
		policyEndpointsManager:       policyEndpointsManager,
		podUpdateBatchPeriodDuration: controllerConfig.PodUpdateBatchPeriodDuration,
		finalizerManager:             finalizerManager,
		maxConcurrentReconciles:      controllerConfig.MaxConcurrentReconciles,
		logger:                       logger,
	}
}

var _ reconcile.Reconciler = (*policyReconciler)(nil)

type policyReconciler struct {
	k8sClient                    client.Client
	policyResolver               resolvers.PolicyReferenceResolver
	policyTracker                resolvers.PolicyTracker
	policyEndpointsManager       policyendpoints.PolicyEndpointsManager
	podUpdateBatchPeriodDuration time.Duration
	finalizerManager             k8s.FinalizerManager

	maxConcurrentReconciles int
	logger                  logr.Logger
}

//+kubebuilder:rbac:groups=networking.k8s.aws,resources=policyendpoints,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=policyendpoints/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=policyendpoints/finalizers,verbs=update
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=applicationnetworkpolicies,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=applicationnetworkpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=applicationnetworkpolicies/finalizers,verbs=update
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=clusternetworkpolicies,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=clusternetworkpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=clusternetworkpolicies/finalizers,verbs=update
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=clusterpolicyendpoints,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=clusterpolicyendpoints/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=clusterpolicyendpoints/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
//+kubebuilder:rbac:groups="networking.k8s.io",resources=networkpolicies,verbs=get;list;watch;update;patch

func (r *policyReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	startTime := time.Now()
	r.logger.Info("Got reconcile request", "resource", request)
	err := r.reconcile(ctx, request)
	r.logger.Info("Reconcile completed", "resource", request, "duration", time.Since(startTime), "success", err == nil)
	return ctrl.Result{}, err
}

func (r *policyReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if err := r.setupIndexes(ctx, mgr.GetFieldIndexer()); err != nil {
		return err
	}
	policyEventChan := make(chan event.GenericEvent)
	policyEventHandler := eventhandlers.NewEnqueueRequestForPolicyEvent(r.policyTracker, r.podUpdateBatchPeriodDuration,
		r.logger.WithName("eventHandler").WithName("policy"))
	podEventHandler := eventhandlers.NewEnqueueRequestForPodEvent(policyEventChan, r.k8sClient, r.policyResolver,
		r.logger.WithName("eventHandler").WithName("pod"))
	nsEventHandler := eventhandlers.NewEnqueueRequestForNamespaceEvent(policyEventChan, r.k8sClient, r.policyResolver,
		r.logger.WithName("eventHandler").WithName("namespace"))
	svcEventHandler := eventhandlers.NewEnqueueRequestForServiceEvent(policyEventChan, r.k8sClient, r.policyResolver,
		r.logger.WithName("eventHandler").WithName("service"))

	if err := mgr.AddHealthzCheck("policy-controller", healthz.Ping); err != nil {
		r.logger.Error(err, "Failed to setup the policy controller healthz check")
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(controllerName).
		Watches(&networking.NetworkPolicy{}, policyEventHandler).
		Watches(&policyinfo.ApplicationNetworkPolicy{}, policyEventHandler).
		Watches(&policyinfo.ClusterNetworkPolicy{}, policyEventHandler).
		Watches(&corev1.Pod{}, podEventHandler).
		Watches(&corev1.Namespace{}, nsEventHandler).
		Watches(&corev1.Service{}, svcEventHandler).
		WatchesRawSource(source.Channel(policyEventChan, policyEventHandler)).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: r.maxConcurrentReconciles,
		}).Complete(r)
}

func (r *policyReconciler) reconcile(ctx context.Context, request reconcile.Request) error {
	var errors []error

	// Handle namespace-scoped resources (NetworkPolicy, ANP)
	if request.Namespace != "" {
		// Try NetworkPolicy
		networkPolicy := &networking.NetworkPolicy{}
		if err := r.k8sClient.Get(ctx, request.NamespacedName, networkPolicy); err == nil {
			if !networkPolicy.DeletionTimestamp.IsZero() {
				if err := r.cleanupNetworkPolicy(ctx, networkPolicy); err != nil {
					errors = append(errors, err)
				}
			} else {
				if err := r.reconcileNetworkPolicy(ctx, networkPolicy); err != nil {
					errors = append(errors, err)
				}
			}
		} else if client.IgnoreNotFound(err) != nil {
			r.logger.Info("Unable to get NetworkPolicy", "resource", request.NamespacedName, "err", err)
			errors = append(errors, err)
		}

		// Try ApplicationNetworkPolicy
		applicationNetworkPolicy := &policyinfo.ApplicationNetworkPolicy{}
		if err := r.k8sClient.Get(ctx, request.NamespacedName, applicationNetworkPolicy); err == nil {
			if !applicationNetworkPolicy.DeletionTimestamp.IsZero() {
				if err := r.cleanupApplicationNetworkPolicy(ctx, applicationNetworkPolicy); err != nil {
					errors = append(errors, err)
				}
			} else {
				if err := r.reconcileApplicationNetworkPolicy(ctx, applicationNetworkPolicy); err != nil {
					errors = append(errors, err)
				}
			}
		} else if client.IgnoreNotFound(err) != nil {
			r.logger.Info("Unable to get ApplicationNetworkPolicy", "resource", request.NamespacedName, "err", err)
			errors = append(errors, err)
		}
	} else {
		// Handle cluster-scoped resources (CNP)
		clusterNetworkPolicy := &policyinfo.ClusterNetworkPolicy{}
		if err := r.k8sClient.Get(ctx, types.NamespacedName{Name: request.Name}, clusterNetworkPolicy); err == nil {
			if !clusterNetworkPolicy.DeletionTimestamp.IsZero() {
				if err := r.cleanupClusterNetworkPolicy(ctx, clusterNetworkPolicy); err != nil {
					errors = append(errors, err)
				}
			} else {
				if err := r.reconcileClusterNetworkPolicy(ctx, clusterNetworkPolicy); err != nil {
					errors = append(errors, err)
				}
			}
		} else if client.IgnoreNotFound(err) != nil {
			r.logger.Info("Unable to get ClusterNetworkPolicy", "resource", request.Name, "err", err)
			errors = append(errors, err)
		}
	}

	// Return constructed error if any occurred
	if len(errors) > 0 {
		var errorMessages []string
		for _, err := range errors {
			errorMessages = append(errorMessages, err.Error())
		}
		return fmt.Errorf("Failed to reconcile NetworkPolicy or ApplicationNetworkPolicy: %s", strings.Join(errorMessages, "; "))
	}
	return nil
}

func (r *policyReconciler) reconcileNetworkPolicy(ctx context.Context, networkPolicy *networking.NetworkPolicy) error {
	start := time.Now()
	defer func() {
		metrics.RecordWorkDuration("NetworkPolicy", time.Since(start))
	}()

	isNewPolicy := len(networkPolicy.Finalizers) == 0

	if err := r.finalizerManager.AddFinalizers(ctx, networkPolicy, policyFinalizerName); err != nil {
		metrics.PolicyReconciliations.WithLabelValues("NetworkPolicy", "error").Inc()
		return err
	}

	if isNewPolicy {
		metrics.OnPolicyCreated("NetworkPolicy")
	}

	if err := r.policyEndpointsManager.Reconcile(ctx, networkPolicy); err != nil {
		metrics.PolicyReconciliations.WithLabelValues("NetworkPolicy", "error").Inc()
		return err
	}
	metrics.PolicyReconciliations.WithLabelValues("NetworkPolicy", "success").Inc()
	return nil
}

func (r *policyReconciler) cleanupNetworkPolicy(ctx context.Context, networkPolicy *networking.NetworkPolicy) error {
	if k8s.HasFinalizer(networkPolicy, policyFinalizerName) {
		r.policyTracker.RemovePolicy(networkPolicy)
		if err := r.policyEndpointsManager.Cleanup(ctx, networkPolicy); err != nil {
			return err
		}
		if err := r.finalizerManager.RemoveFinalizers(ctx, networkPolicy, policyFinalizerName); err != nil {
			return err
		}
		metrics.OnPolicyDeleted("NetworkPolicy")
	}
	return nil
}

func (r *policyReconciler) reconcileApplicationNetworkPolicy(ctx context.Context, applicationNetworkPolicy *policyinfo.ApplicationNetworkPolicy) error {
	start := time.Now()
	defer func() {
		metrics.RecordWorkDuration("ApplicationNetworkPolicy", time.Since(start))
	}()

	isNewPolicy := len(applicationNetworkPolicy.Finalizers) == 0

	if err := r.finalizerManager.AddFinalizers(ctx, applicationNetworkPolicy, anpFinalizerName); err != nil {
		metrics.PolicyReconciliations.WithLabelValues("ApplicationNetworkPolicy", "error").Inc()
		return err
	}

	if isNewPolicy {
		metrics.OnPolicyCreated("ApplicationNetworkPolicy")
	}

	if err := r.policyEndpointsManager.ReconcileANP(ctx, applicationNetworkPolicy); err != nil {
		metrics.PolicyReconciliations.WithLabelValues("ApplicationNetworkPolicy", "error").Inc()
		return err
	}
	metrics.PolicyReconciliations.WithLabelValues("ApplicationNetworkPolicy", "success").Inc()
	return nil
}

func (r *policyReconciler) cleanupApplicationNetworkPolicy(ctx context.Context, applicationNetworkPolicy *policyinfo.ApplicationNetworkPolicy) error {
	if k8s.HasFinalizer(applicationNetworkPolicy, anpFinalizerName) {
		r.policyTracker.RemoveGenericPolicy(applicationNetworkPolicy)
		if err := r.policyEndpointsManager.CleanupANP(ctx, applicationNetworkPolicy); err != nil {
			return err
		}
		if err := r.finalizerManager.RemoveFinalizers(ctx, applicationNetworkPolicy, anpFinalizerName); err != nil {
			return err
		}
		metrics.OnPolicyDeleted("ApplicationNetworkPolicy")
	}
	return nil
}

func (r *policyReconciler) reconcileClusterNetworkPolicy(ctx context.Context, cnp *policyinfo.ClusterNetworkPolicy) error {
	start := time.Now()
	defer func() {
		metrics.RecordWorkDuration("ClusterNetworkPolicy", time.Since(start))
	}()

	isNewPolicy := len(cnp.Finalizers) == 0

	if err := r.finalizerManager.AddFinalizers(ctx, cnp, cnpFinalizerName); err != nil {
		metrics.PolicyReconciliations.WithLabelValues("ClusterNetworkPolicy", "error").Inc()
		return err
	}

	if isNewPolicy {
		metrics.OnPolicyCreated("ClusterNetworkPolicy")
	}

	if err := r.policyEndpointsManager.ReconcileCNP(ctx, cnp); err != nil {
		metrics.PolicyReconciliations.WithLabelValues("ClusterNetworkPolicy", "error").Inc()
		return err
	}
	metrics.PolicyReconciliations.WithLabelValues("ClusterNetworkPolicy", "success").Inc()
	return nil
}

func (r *policyReconciler) cleanupClusterNetworkPolicy(ctx context.Context, cnp *policyinfo.ClusterNetworkPolicy) error {
	if k8s.HasFinalizer(cnp, cnpFinalizerName) {
		r.policyTracker.RemoveGenericPolicy(cnp)
		if err := r.policyEndpointsManager.CleanupCNP(ctx, cnp); err != nil {
			return err
		}
		if err := r.finalizerManager.RemoveFinalizers(ctx, cnp, cnpFinalizerName); err != nil {
			return err
		}
		metrics.OnPolicyDeleted("ClusterNetworkPolicy")
	}
	return nil
}

func (r *policyReconciler) setupIndexes(ctx context.Context, fieldIndexer client.FieldIndexer) error {
	if err := fieldIndexer.IndexField(ctx, &policyinfo.PolicyEndpoint{}, policyendpoints.IndexKeyPolicyReferenceName,
		policyendpoints.IndexFunctionPolicyReferenceName); err != nil {
		return err
	}
	if err := fieldIndexer.IndexField(ctx, &policyinfo.ClusterPolicyEndpoint{}, policyendpoints.IndexKeyClusterPolicyReferenceName,
		policyendpoints.IndexFunctionClusterPolicyReferenceName); err != nil {
		return err
	}
	return nil
}
