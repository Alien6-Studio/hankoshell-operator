// Package workloadauth defines public, closed authentication transactions.
// It has no provider, Kubernetes client or credential interface.
package workloadauth

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

const Schema = "hanko.sh/workload-auth-transition/v1alpha1"
const JournalKey = "hanko.sh/workload-auth-transition"
const ApprovalKey = "hanko.sh/workload-auth-approval"
const ReviewKey = "hanko.sh/workload-auth-review"
const CleanupKey = "hanko.sh/workload-auth-cleanup"

var ErrPrecondition = errors.New("authentication transaction precondition failed")
var bearerShape = regexp.MustCompile(`^eyJ[a-zA-Z0-9_-]+[.][a-zA-Z0-9_-]+[.][a-zA-Z0-9_-]+$`)
var reference = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

type Journal struct {
	Schema                   string `json:"schema"`
	OwnerUID                 string `json:"ownerUID"`
	Generation               int64  `json:"generation"`
	RequestID                string `json:"requestID"`
	ClientUUID               string `json:"clientUUID"`
	PreviousMode             string `json:"previousMode"`
	DesiredMode              string `json:"desiredMode"`
	TrustUID                 string `json:"trustUID"`
	ProviderID               string `json:"providerID"`
	BindingRevision          string `json:"bindingRevision"`
	WorkloadUID              string `json:"workloadUID"`
	PreparedWorkloadRevision string `json:"preparedWorkloadRevision"`
	NativeStateHash          string `json:"nativeStateHash"`
	AppliedStateHash         string `json:"appliedStateHash"`
	PlanHash                 string `json:"planHash"`
	Step                     string `json:"step"`
	// Attempted is persisted before CREATE/PUT. Absence after uncertain CREATE
	// requires review, rather than a blind retry with a duplicate identity.
	Attempted bool   `json:"attempted"`
	SecretUID string `json:"secretUID,omitempty"`
}

// Approval is administrator authorization of this exact prepared transaction.
// An annotation avoids a self-referential spec-generation/binding hash: review
// does not change the generation it approves. Status is never authorization.
type Approval struct {
	Strategy                 string `json:"strategy"`
	OwnerUID                 string `json:"ownerUID"`
	Generation               int64  `json:"generation"`
	RequestID                string `json:"requestID"`
	ExpectedClientUUID       string `json:"expectedClientUUID"`
	ReviewedStateHash        string `json:"reviewedStateHash"`
	BindingRevision          string `json:"bindingRevision"`
	PreparedWorkloadRevision string `json:"preparedWorkloadRevision"`
	PreviousMode             string `json:"previousMode"`
	DesiredMode              string `json:"desiredMode"`
	TrustUID                 string `json:"trustUID"`
	ProviderID               string `json:"providerID"`
	WorkloadUID              string `json:"workloadUID"`
	PlanHash                 string `json:"planHash"`
	PreparationApproved      bool   `json:"preparationApproved"`
}
type Review struct {
	RequestID       string `json:"requestID"`
	ClientUUID      string `json:"clientUUID"`
	BindingRevision string `json:"bindingRevision"`
	WorkloadUID     string `json:"workloadUID"`
	PlanHash        string `json:"planHash"`
}
type Cleanup struct {
	Review
	SecretUID string `json:"secretUID"`
}

func Decode(value string, target any) error {
	if len(value) == 0 || len(value) > 8192 {
		return ErrPrecondition
	}
	d := json.NewDecoder(strings.NewReader(value))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return ErrPrecondition
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrPrecondition
	}
	b, err := json.Marshal(target)
	if err != nil || string(b) != value {
		return ErrPrecondition
	}
	return nil
}
func Encode(value any) string { b, _ := json.Marshal(value); return string(b) }
func ParseJournal(value string) (*Journal, error) {
	if value == "" {
		return nil, nil
	}
	var j Journal
	if Decode(value, &j) != nil || !j.Valid() {
		return nil, ErrPrecondition
	}
	return &j, nil
}
func (j Journal) Valid() bool {
	for _, v := range []string{j.OwnerUID, j.RequestID, j.ClientUUID, j.TrustUID, j.ProviderID, j.WorkloadUID, j.PreparedWorkloadRevision} {
		if !reference.MatchString(v) || bearerShape.MatchString(v) {
			return false
		}
	}
	for _, v := range []string{j.BindingRevision, j.NativeStateHash, j.AppliedStateHash, j.PlanHash} {
		if !iamcontract.ValidDigest(v) {
			return false
		}
	}
	return j.Schema == Schema && j.Generation >= 1 && slices.Contains([]string{"Absent", "Secret", "Kubernetes"}, j.PreviousMode) && slices.Contains([]string{"Secret", "Kubernetes"}, j.DesiredMode) && slices.Contains([]string{"Prepared", "ModeApplied", "AuthReviewed", "OutputsCleaned", "Committed"}, j.Step) && (j.SecretUID == "" || reference.MatchString(j.SecretUID))
}
func (a Approval) Matches(j Journal) bool {
	return a.Strategy == "CoordinatedCutover" && a.OwnerUID == j.OwnerUID && a.Generation == j.Generation && a.RequestID == j.RequestID && a.ExpectedClientUUID == j.ClientUUID && a.ReviewedStateHash == j.NativeStateHash && a.BindingRevision == j.BindingRevision && a.PreparedWorkloadRevision == j.PreparedWorkloadRevision && a.PreviousMode == j.PreviousMode && a.DesiredMode == j.DesiredMode && a.TrustUID == j.TrustUID && a.ProviderID == j.ProviderID && a.WorkloadUID == j.WorkloadUID && a.PlanHash == j.PlanHash && a.PreparationApproved
}
func (r Review) Matches(j Journal) bool {
	return r.RequestID == j.RequestID && r.ClientUUID == j.ClientUUID && r.BindingRevision == j.BindingRevision && r.WorkloadUID == j.WorkloadUID && r.PlanHash == j.PlanHash
}
func Hash(purpose string, value any) string {
	b, _ := json.Marshal(value)
	return string(iamcontract.Hash(iamcontract.Version, "workload-authentication", purpose, b))
}
