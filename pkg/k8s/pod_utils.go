package k8s

import (
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	podIPAnnotation = "vpc.amazonaws.com/pod-ips"
)

// GetPodIP returns the pod IP from the pod status or from the pod annotation.
func GetPodIP(pod *corev1.Pod) string {
	if len(pod.Status.PodIP) > 0 {
		return pod.Status.PodIP
	} else {
		return pod.Annotations[podIPAnnotation]
	}
}

// LookupContainerPortAndName returns numerical containerPort and portName for specific port and protocol
func LookupContainerPortAndName(pod *corev1.Pod, port intstr.IntOrString, protocol corev1.Protocol) (int32, string, error) {
	for _, podContainer := range pod.Spec.Containers {
		for _, podPort := range podContainer.Ports {
			if podPort.Protocol != protocol {
				continue
			}
			switch port.Type {
			case intstr.String:
				if podPort.Name == port.StrVal {
					return podPort.ContainerPort, podPort.Name, nil
				}
			case intstr.Int:
				if podPort.ContainerPort == port.IntVal {
					return podPort.ContainerPort, podPort.Name, nil
				}
			}
		}
	}
	if port.Type == intstr.Int {
		return port.IntVal, "", nil
	}
	return 0, "", errors.Errorf("unable to find port %s on pod %s", port.String(), NamespacedName(pod))
}

// StripDownPodTransformFunc is a transform function that strips down node to reduce memory usage.
// see details in [stripDownNodeObject].
func StripDownPodTransformFunc(obj interface{}) (interface{}, error) {
	if pod, ok := obj.(*corev1.Pod); ok {
		return stripDownPodObject(pod), nil
	}
	return obj, nil
}

// stripDownPodObject provides an stripDown version of pod to reduce memory usage.
// NOTE: it's safe to return in-place mutated pod object when client-go 1.27+.
func stripDownPodObject(pod *corev1.Pod) *corev1.Pod {
	pod.ObjectMeta = metav1.ObjectMeta{
		Name:              pod.Name,
		Namespace:         pod.Namespace,
		UID:               pod.UID,
		DeletionTimestamp: pod.DeletionTimestamp,
		Labels:            pod.Labels,
		Annotations: map[string]string{
			podIPAnnotation: pod.Annotations[podIPAnnotation],
		},
	}
	pod.Spec = corev1.PodSpec{}
	pod.Status = corev1.PodStatus{
		HostIP:  pod.Status.HostIP,
		HostIPs: pod.Status.HostIPs,
		PodIP:   pod.Status.PodIP,
	}
	return pod
}
