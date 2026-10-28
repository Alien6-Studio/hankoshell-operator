package main

import (
	"testing"
)

func TestRequiredInstallationNeverSilentlySkipsVerification(t *testing.T) {
	if err := verifyInstallation(runtimeConfig{}); err != nil {
		t.Fatal(err)
	}
	for _, config := range []runtimeConfig{
		{installationRequired: true},
		{installationCheckOnly: true},
		{installationConfigMap: "approved-contract"},
		{installationDigest: "approved-hash"},
		{installationContract: "/contract.json", installationConfigMap: "approved-contract", installationDigest: "approved-hash"},
	} {
		if err := verifyInstallation(config); err == nil {
			t.Fatal("incomplete OLM verification was silently skipped")
		}
	}
}
