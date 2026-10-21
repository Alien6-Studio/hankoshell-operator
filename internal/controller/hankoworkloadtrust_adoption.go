package controller

import (
	"context"
	"strconv"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadtrust"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func workloadTrustCandidate(s *workloadSnapshot) *api.AdoptionCandidateStatus {
	if !qualifiedWorkloadRead(s) {
		return incompleteTargetCandidate(&s.trust)
	}
	p := s.provider
	i := s.plan.Intent()
	facts := []adoption.Fact{}
	desired := []adoption.Fact{}
	text := func(field, current, want string) {
		f := adoption.Fact{Domain: "workload-trust", Identity: p.InternalID, Object: p.Alias, Field: field, Classification: adoption.Supported, RoundTrip: adoption.Lossless, Value: adoption.Value{Text: current}}
		facts = append(facts, f)
		f.Value.Text = want
		desired = append(desired, f)
	}
	text("providerType", p.ProviderID, "kubernetes")
	text("alias", p.Alias, i.Alias)
	text("workloadIssuer", p.Config.Issuer, i.Issuer)
	text("workloadDiscovery", p.Config.DiscoveryURL, i.DiscoveryURL)
	text("workloadAge", strconv.FormatInt(p.Config.MaxAge, 10), strconv.FormatInt(i.MaxAge, 10))
	text("workloadSkew", p.Config.ClockSkew, "0")
	text("workloadAnchor", workloadtrust.Digest("anchor", []string{i.NamespaceUID, i.CAHash}), workloadtrust.Digest("anchor", []string{i.NamespaceUID, i.CAHash}))
	text("workloadReferences", workloadtrust.Digest("approved-references", s.trust.Spec), workloadtrust.Digest("approved-references", s.trust.Spec))
	owner := "unmarked"
	findings := []adoption.Finding{}
	if p.Config.Owner != "" || p.Config.Journal != "" || p.Config.Receipt != "" {
		if workloadOwnershipMatches(s) && p.Config.Receipt != "" {
			// Normalize only this exact durable common receipt, so a lost ACK or
			// status patch reconstructs the same originally approved candidate.
			receipt, err := adoption.ParseReceipt(p.Config.Receipt)
			if err != nil || receipt.TargetKind != "HankoWorkloadTrust" || receipt.TargetUID != string(s.trust.UID) {
				owner = "foreign"
			}
		} else {
			owner = "foreign"
		}
		if owner == "foreign" {
			findings = append(findings, adoption.Finding{Code: "foreign_ownership", Domain: "workload-trust", Message: "provider ownership metadata requires independent administrator review", Blocking: true})
		}
	}
	text("owner", owner, string(s.trust.UID))
	flag := p.Enabled
	wantFlag := true
	facts = append(facts, adoption.Fact{Domain: "workload-trust", Identity: p.InternalID, Object: p.Alias, Field: "enabled", Classification: adoption.Supported, RoundTrip: adoption.Lossless, Value: adoption.Value{Flag: &flag}})
	desired = append(desired, adoption.Fact{Domain: "workload-trust", Identity: p.InternalID, Object: p.Alias, Field: "enabled", Classification: adoption.Supported, RoundTrip: adoption.Lossless, Value: adoption.Value{Flag: &wantFlag}})
	provider := s.source.identity
	provider.ObjectIDs = []string{p.InternalID}
	target := adoption.TargetIdentity{Kind: "HankoWorkloadTrust", Namespace: s.trust.Namespace, Name: s.trust.Name, UID: string(s.trust.UID), Generation: s.trust.Generation, ImportRef: s.trust.Labels[importedByLabel], TenantRef: s.trust.Labels["hanko.sh/tenant"]}
	return candidateStatus(adoption.Build(target, provider, adoption.Observation{Facts: facts, Complete: true, Findings: findings}, desired))
}

func (r *HankoWorkloadTrustReconciler) acquireWorkloadTrust(ctx context.Context, s *workloadSnapshot, approval adoption.Approval) (ctrl.Result, error) {
	candidate := workloadTrustCandidate(s)
	if s.provider == nil || candidate == nil || !candidate.Approvable || candidate.CandidateHash != approval.CandidateHash {
		return r.workloadStatus(ctx, &s.trust, s, "AdoptionApprovalRequired", false)
	}
	receipt, err := (adoption.Receipt{ContractVersion: adoption.Version, TargetKind: "HankoWorkloadTrust", TargetUID: string(s.trust.UID), CandidateHash: approval.CandidateHash}).Canonical()
	if err != nil {
		return r.workloadStatus(ctx, &s.trust, s, "OwnershipConflict", false)
	}
	if workloadOwnershipMatches(s) && s.provider.Config.Receipt == receipt {
		if s.checkpoint == nil || s.checkpoint.Step != "Owned" {
			return r.workloadCheckpoint(ctx, s, "Owned", false)
		}
		return r.workloadStatus(ctx, &s.trust, s, "Observed", workloadConfigurationMatches(s))
	}
	if s.provider.Config.Owner != "" || s.provider.Config.Journal != "" || s.provider.Config.Receipt != "" {
		return r.workloadStatus(ctx, &s.trust, s, "OwnershipConflict", false)
	}
	if s.checkpoint == nil {
		return r.workloadCheckpoint(ctx, s, "AdoptionPending", false)
	}
	if s.checkpoint.Step != "AdoptionPending" {
		return r.workloadStatus(ctx, &s.trust, s, "OwnershipConflict", false)
	}
	fresh, err := r.workloadSnapshot(ctx, client.ObjectKeyFromObject(&s.trust), true, s.provider.InternalID)
	if err != nil || s.plan.Validate(freshPlan(fresh)) != nil || !sameWorkloadProvider(s.provider, providerOf(fresh)) || effectiveWorkloadTrustMode(&fresh.trust) != ModeObserve || workloadTrustCandidate(fresh).CandidateHash != approval.CandidateHash {
		return r.workloadStatus(ctx, &s.trust, s, "AdoptionApprovalRequired", false)
	}
	journal, err := fresh.plan.Journal(nativeWorkloadStateHash(*fresh.provider), "Acquired")
	if err != nil {
		return r.workloadStatus(ctx, &s.trust, s, "OwnershipConflict", false)
	}
	err = fresh.writer.client.AcquireKubernetesWorkloadTrustOwnership(ctx, fresh.trust.Spec.RealmRef, *fresh.provider, string(fresh.trust.UID), journal, receipt)
	after, readErr := r.workloadSnapshot(ctx, client.ObjectKeyFromObject(&s.trust), true, s.provider.InternalID)
	if readErr != nil || fresh.plan.Validate(freshPlan(after)) != nil || !workloadOwnershipMatches(after) || after.provider.Config.Receipt != receipt || after.provider.Config.Journal != journal || nativeWorkloadStateHash(*after.provider) != nativeWorkloadStateHash(*fresh.provider) {
		_ = err
		return r.workloadStatus(ctx, &s.trust, s, "IncompleteProviderRead", false)
	}
	if _, err := r.workloadCheckpoint(ctx, after, "Owned", false); err != nil {
		return ctrl.Result{}, err
	}
	return r.workloadStatus(ctx, &after.trust, after, "Observed", workloadConfigurationMatches(after))
}
