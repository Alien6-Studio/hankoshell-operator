package controller

import (
	"context"
	"errors"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	"github.com/Alien6-Studio/hankoshell-operator/internal/selfupdate"
	"github.com/Alien6-Studio/hankoshell-operator/internal/version"
)

// executeAgentUpdate runs the Hub-commanded self-update. Any refusal or
// failure is reported as an error phase so Hub keeps the command pending and
// re-delivers it on the next heartbeat; success pins the operator's own
// Deployment to the commanded digest, so the kubelet replaces this pod and no
// requeue is scheduled. The new binary's first heartbeat reports the
// commanded version, which clears the command on Hub.
func (r *HankoTenantReconciler) executeAgentUpdate(
	ctx context.Context,
	tenant *hankoshv1alpha1.HankoTenant,
	patch client.Patch,
	hubClient *hub.Client,
	command *hub.AgentUpdateCommand,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("hub requested agent self-update",
		"tenant", tenant.Name, "version", command.Version, "digest", command.Digest)

	if version.Agent == command.Version {
		// Already converged (e.g. the rollout finished between heartbeats):
		// the next status report clears the command on Hub.
		return ctrl.Result{RequeueAfter: requeueInterval}, nil
	}
	if r.AgentUpdate == nil {
		return r.setError(ctx, hubClient, tenant, patch, "AgentUpdateUnsupported",
			errors.New("this operator deployment is not configured for hub-commanded self-update; update it with the reviewed release procedure"))
	}

	engine := &selfupdate.Engine{
		Writer: r.Client,
		Reader: r.ClusterIdentityReader,
		Config: *r.AgentUpdate,
	}
	image, err := engine.Run(ctx, command)
	if err != nil {
		return r.setError(ctx, hubClient, tenant, patch, "AgentUpdateFailed", err)
	}
	logger.Info("agent self-update applied; awaiting rollout of the pinned image",
		"tenant", tenant.Name, "image", image)
	return ctrl.Result{}, nil
}
