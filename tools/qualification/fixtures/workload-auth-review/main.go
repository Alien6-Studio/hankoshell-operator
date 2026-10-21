// Command workload-auth-review creates fixture approvals with the production contract.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"os"

	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadauth"
)

func main() {
	action := flag.String("action", "", "approval, review or cleanup")
	secretUID := flag.String("secret-uid", "", "approved canonical output UID")
	flag.Parse()
	if err := execute(*action, *secretUID); err != nil {
		slog.Error("fixture review rejected")
		os.Exit(1)
	}
}

func execute(action, secretUID string) error {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 8193))
	if err != nil {
		return err
	}
	j, err := workloadauth.ParseJournal(string(data))
	if err != nil || j == nil {
		return workloadauth.ErrPrecondition
	}
	r := workloadauth.Review{RequestID: j.RequestID, ClientUUID: j.ClientUUID, BindingRevision: j.BindingRevision, WorkloadUID: j.WorkloadUID, PlanHash: j.PlanHash}
	key, value := "", ""
	switch action {
	case "approval":
		a := workloadauth.Approval{Strategy: "CoordinatedCutover", OwnerUID: j.OwnerUID, Generation: j.Generation, RequestID: j.RequestID, ExpectedClientUUID: j.ClientUUID, ReviewedStateHash: j.NativeStateHash, BindingRevision: j.BindingRevision, PreparedWorkloadRevision: j.PreparedWorkloadRevision, PreviousMode: j.PreviousMode, DesiredMode: j.DesiredMode, TrustUID: j.TrustUID, ProviderID: j.ProviderID, WorkloadUID: j.WorkloadUID, PlanHash: j.PlanHash, PreparationApproved: true}
		if !a.Matches(*j) {
			return workloadauth.ErrPrecondition
		}
		key, value = workloadauth.ApprovalKey, workloadauth.Encode(a)
	case "review":
		key, value = workloadauth.ReviewKey, workloadauth.Encode(r)
	case "cleanup":
		if secretUID == "" {
			return workloadauth.ErrPrecondition
		}
		key, value = workloadauth.CleanupKey, workloadauth.Encode(workloadauth.Cleanup{Review: r, SecretUID: secretUID})
	default:
		return workloadauth.ErrPrecondition
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{key: value})
}
