package adoption

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

const (
	SourceAnnotation    = "hanko.sh/adoption-source"
	ContractAnnotation  = "hanko.sh/adoption-contract"
	CandidateAnnotation = "hanko.sh/adoption-candidate"
	ReceiptKey          = "hanko.sh/adoption-receipt"
	ApplicationOwnerKey = "hanko.sh/application-owner"
	RoleOwnerKey        = "hanko.sh/role-owner"
	ClientOwnerKindKey  = "hanko.sh/client-owner-kind"
	ClientOwnerUIDKey   = "hanko.sh/client-owner-uid"
	MaxReceiptBytes     = 512
)

var (
	ErrApproval         = errors.New("invalid adoption approval metadata")
	ErrApprovalConflict = errors.New("legacy and common adoption approvals conflict")
	ErrReceipt          = errors.New("invalid adoption receipt")
	hashPattern         = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	sourcePattern       = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
)

// Approval comes from target metadata, never status. Source alone is a read-only
// selection; the contract and candidate must be supplied together to approve.
type Approval struct {
	Source        string
	Contract      ContractVersion
	CandidateHash string
	Requested     bool
}

func ParseApproval(annotations map[string]string) (Approval, error) {
	a := Approval{Source: annotations[SourceAnnotation], Contract: ContractVersion(annotations[ContractAnnotation]), CandidateHash: annotations[CandidateAnnotation]}
	_, contractPresent := annotations[ContractAnnotation]
	_, candidatePresent := annotations[CandidateAnnotation]
	_, sourcePresent := annotations[SourceAnnotation]
	a.Requested = contractPresent || candidatePresent
	if sourcePresent && (len(a.Source) > 253 || !sourcePattern.MatchString(a.Source) || strings.Contains(a.Source, "..")) {
		return a, ErrApproval
	}
	if !a.Requested {
		return a, nil
	}
	_, legacyUUID := annotations["hanko.sh/migrate-keycloak-client-uuid"]
	_, legacyObservation := annotations["hanko.sh/migrate-keycloak-observation"]
	if legacyUUID || legacyObservation {
		return a, ErrApprovalConflict
	}
	if !sourcePresent || !contractPresent || !candidatePresent || a.Contract != Version || !hashPattern.MatchString(a.CandidateHash) {
		return a, ErrApproval
	}
	return a, nil
}

// Receipt is a small immutable acquisition checkpoint. It is neither an
// executable plan nor deletion consent. It contains no credential material.
type Receipt struct {
	ContractVersion ContractVersion `json:"contractVersion"`
	TargetKind      string          `json:"targetKind"`
	TargetUID       string          `json:"targetUID"`
	CandidateHash   string          `json:"candidateHash"`
}

func (r Receipt) Canonical() (string, error) {
	if r.ContractVersion != Version || !leafKind(r.TargetKind) || r.TargetUID == "" || len(r.TargetUID) > MaxProviderIDBytes || strings.ContainsAny(r.TargetUID, "\x00\r\n") || !hashPattern.MatchString(r.CandidateHash) {
		return "", ErrReceipt
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) > MaxReceiptBytes {
		return "", ErrReceipt
	}
	return string(b), nil
}

func ParseReceipt(value string) (Receipt, error) {
	var r Receipt
	if len(value) > MaxReceiptBytes || json.Unmarshal([]byte(value), &r) != nil {
		return r, ErrReceipt
	}
	canonical, err := r.Canonical()
	if err != nil || canonical != value {
		return r, ErrReceipt
	}
	return r, nil
}

func leafKind(kind string) bool {
	return kind == "HankoApplication" || kind == "HankoRole" || kind == "HankoServiceAccount"
}

func ReservedAttribute(key string) bool {
	return (strings.HasPrefix(key, "hanko.sh/") && strings.Contains(key, "owner")) || key == ApplicationOwnerKey || key == RoleOwnerKey || key == ClientOwnerKindKey || key == ClientOwnerUIDKey || key == ReceiptKey || key == "hanko.sh/resource-server-ownership"
}
