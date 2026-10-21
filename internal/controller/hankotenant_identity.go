package controller

import (
	"context"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
)

func (r *HankoTenantReconciler) enrollmentIdentity(ctx context.Context, clusterName string) (hub.EnrollmentIdentity, error) {
	name := strings.Join(strings.Fields(clusterName), " ")
	if (clusterName != "" && name == "") || utf8.RuneCountInString(name) > 80 {
		return hub.EnrollmentIdentity{}, fmt.Errorf("clusterName must contain 1 to 80 characters when provided")
	}
	for _, char := range name {
		if !unicode.IsLetter(char) && !unicode.IsNumber(char) && !strings.ContainsRune(" ._-", char) {
			return hub.EnrollmentIdentity{}, fmt.Errorf("clusterName may contain only letters, numbers, spaces, dots, underscores and hyphens")
		}
	}
	// A cache read would need list/watch permission for every Namespace. This
	// reader is wired to the API directly and needs GET kube-system only.
	if r.ClusterIdentityReader == nil {
		return hub.EnrollmentIdentity{}, fmt.Errorf("cluster identity reader is not configured; refusing enrollment without the kube-system Namespace UID")
	}
	var namespace corev1.Namespace
	if err := r.ClusterIdentityReader.Get(ctx, client.ObjectKey{Name: "kube-system"}, &namespace); err != nil {
		return hub.EnrollmentIdentity{}, fmt.Errorf("read kube-system Namespace UID before enrollment (requires get on this Namespace): %w", err)
	}
	uid := string(namespace.UID)
	if uid == "" || len(uid) > 128 {
		return hub.EnrollmentIdentity{}, fmt.Errorf("kube-system Namespace UID is empty or invalid; refusing enrollment without a stable cluster identity")
	}
	for _, char := range uid {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && !strings.ContainsRune("._:-", char) { //nolint:staticcheck // QF1001: range-negation guard is clearer than the De Morgan rewrite.
			return hub.EnrollmentIdentity{}, fmt.Errorf("kube-system Namespace UID contains invalid characters; refusing enrollment")
		}
	}
	return hub.EnrollmentIdentity{ClusterName: name, ClusterUID: uid}, nil
}
