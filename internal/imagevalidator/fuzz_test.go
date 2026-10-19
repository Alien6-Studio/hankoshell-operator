package imagevalidator

import (
	"encoding/json"
	"strings"
	"testing"
)

func FuzzImageReference(f *testing.F) {
	digest := "@sha256:" + strings.Repeat("a", 64)
	for _, seed := range []string{"registry.example.test/team/image" + digest, "registry.example.test.evil/team/image" + digest, "registry.example.test/teamevil/image:1", "registry.example.test/team/image:mutable", "https://registry.example.test/team/image", ""} {
		f.Add(seed)
	}
	validator := NewWithPrefixes("registry.example.test/team")
	f.Fuzz(func(t *testing.T, image string) {
		if validator.ValidateImageRef(image) == nil && !strings.HasPrefix(image, "registry.example.test/team/") && !strings.HasPrefix(image, "registry.example.test/team:") && !strings.HasPrefix(image, "registry.example.test/team@") && image != "registry.example.test/team" {
			t.Fatal("registry or repository boundary escaped")
		}
		if immutableImage(image) && (!strings.Contains(image, "@sha256:") || strings.Contains(strings.Split(image, "@")[0], ":mutable")) {
			t.Fatal("mutable image accepted for execution")
		}
	})
}

func FuzzImageApprovalPolicy(f *testing.F) {
	approval := Approval{Purpose: Keycloak, Image: "registry.example.test/team/image@sha256:" + strings.Repeat("a", 64), Revision: strings.Repeat("b", 40), KeyFile: "publisher.pub"}
	seed, _ := json.Marshal(approvalPolicy{Version: 1, Approvals: []Approval{approval}})
	for _, data := range [][]byte{seed, []byte(`{"version":1,"approvals":[]}`), []byte(`{"version":2,"version":1,"approvals":[]}`), []byte(strings.Repeat(" ", maxPolicyBytes+1))} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		policy, err := decodePolicy(data)
		if err != nil {
			return
		}
		if policy.Version != 1 || len(policy.Approvals) > 128 || len(data) > maxPolicyBytes {
			t.Fatal("unbounded image policy accepted")
		}
		for _, a := range policy.Approvals {
			if !validApproval(a) {
				t.Fatal("unqualified publisher approval accepted")
			}
		}
		if _, err := decodePolicy(append(append([]byte{}, data...), []byte(" {}")...)); err == nil {
			t.Fatal("trailing image approval accepted")
		}
	})
}
