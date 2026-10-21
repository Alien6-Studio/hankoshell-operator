package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

type effectiveRealmIAMProfile struct {
	Name     string
	Hash     string
	Security *hankoshv1alpha1.RealmSecurityProfile
}

func resolveRealmIAMProfile(ctx context.Context, reader client.Reader, realm *hankoshv1alpha1.HankoRealm) (effectiveRealmIAMProfile, error) {
	if realm.Spec.IAMProfileRef != "" && realm.Spec.SecurityProfile != nil {
		return effectiveRealmIAMProfile{}, fmt.Errorf("iamProfileRef and securityProfile are mutually exclusive")
	}
	if realm.Spec.IAMProfileRef != "" {
		var profile hankoshv1alpha1.HankoIAMProfile
		key := client.ObjectKey{Name: realm.Spec.IAMProfileRef, Namespace: realm.Namespace}
		if err := reader.Get(ctx, key, &profile); err != nil {
			return effectiveRealmIAMProfile{}, fmt.Errorf("get HankoIAMProfile %q: %w", realm.Spec.IAMProfileRef, err)
		}
		if err := validateIAMSecurityProfile(&profile.Spec.Security); err != nil {
			return effectiveRealmIAMProfile{}, fmt.Errorf("hanko IAM profile %q is invalid: %w", profile.Name, err)
		}
		return effectiveRealmIAMProfile{
			Name: profile.Name, Hash: hashIAMSecurityProfile(&profile.Spec.Security), Security: profile.Spec.Security.DeepCopy(),
		}, nil
	}
	if realm.Spec.SecurityProfile == nil {
		return effectiveRealmIAMProfile{}, nil
	}
	if err := validateIAMSecurityProfile(realm.Spec.SecurityProfile); err != nil {
		return effectiveRealmIAMProfile{}, fmt.Errorf("inline securityProfile is invalid: %w", err)
	}
	return effectiveRealmIAMProfile{
		Name: "inline", Hash: hashIAMSecurityProfile(realm.Spec.SecurityProfile), Security: realm.Spec.SecurityProfile.DeepCopy(),
	}, nil
}

func hashIAMSecurityProfile(profile *hankoshv1alpha1.RealmSecurityProfile) string {
	if profile == nil {
		return ""
	}
	payload, err := json.Marshal(profile)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateIAMSecurityProfile(profile *hankoshv1alpha1.RealmSecurityProfile) error {
	if profile == nil {
		return nil
	}
	switch profile.MFAPolicy {
	case "", "none", "optional", "required":
	default:
		return fmt.Errorf("mfaPolicy %q is unsupported", profile.MFAPolicy)
	}
	if profile.PasswordMinLength > 0 && profile.PasswordMinLength < 8 {
		return fmt.Errorf("passwordMinLength must be at least 8")
	}
	lifetime, err := positiveDuration("sessionLifetime", profile.SessionLifetime)
	if err != nil {
		return err
	}
	idle, err := positiveDuration("sessionIdleTimeout", profile.SessionIdleTimeout)
	if err != nil {
		return err
	}
	if lifetime > 0 && idle > lifetime {
		return fmt.Errorf("sessionIdleTimeout must not exceed sessionLifetime")
	}
	if profile.BruteForce != nil && profile.BruteForce.Enabled {
		if profile.BruteForce.MaxFailures < 1 {
			return fmt.Errorf("bruteForce.maxFailures must be at least 1 when enabled")
		}
		if _, err := positiveDuration("bruteForce.waitIncrements", profile.BruteForce.WaitIncrements); err != nil {
			return err
		}
	}
	return nil
}

func positiveDuration(field, value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a Go duration: %w", field, err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", field)
	}
	return duration, nil
}
