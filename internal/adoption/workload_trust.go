package adoption

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

// Workload fields cannot accidentally widen an unrelated leaf's evidence map.
func validWorkloadTrustFact(f Fact) bool {
	if !strings.HasPrefix(f.Field, "workload") && f.Domain != "workload-trust" {
		return true
	}
	if f.Domain != "workload-trust" || f.Classification != Supported || f.RoundTrip != Lossless || len(f.Value.Set) != 0 {
		return false
	}
	if f.Field == "enabled" {
		return f.Value.Flag != nil && f.Value.Text == ""
	}
	if f.Value.Flag != nil {
		return false
	}
	return validWorkloadTrustText(f.Field, f.Value.Text)
}

func validWorkloadTrustText(field, value string) bool {
	switch field {
	case "providerType":
		return value == "kubernetes"
	case "alias", "owner":
		return value != "" && !strings.ContainsAny(value, "\r\n\t")
	case "workloadIssuer", "workloadDiscovery":
		if field == "workloadDiscovery" && value == "" {
			return true
		}
		return validWorkloadTrustURL(value)
	case "workloadAge":
		n, err := strconv.ParseInt(value, 10, 64)
		return err == nil && n >= 600 && n <= 3600 && strconv.FormatInt(n, 10) == value
	case "workloadSkew":
		return value == "0" || value == "10"
	case "workloadAnchor", "workloadReferences":
		return iamcontract.ValidDigest(value)
	default:
		return false
	}
}

func validWorkloadTrustURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && u.RawPath == ""
}
