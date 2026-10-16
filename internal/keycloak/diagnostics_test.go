package keycloak

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestKeycloakErrorsAreTypedAndNeverIncludeNativeDiagnostics(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError} {
		body := &measuredKeycloakBody{Reader: strings.NewReader(`{"error":"credential=secret-sentinel"}`)}
		kc := responseBudgetClient(status, -1, body)
		_, err := kc.ListRealms(context.Background())
		var statusErr *StatusError
		if !errors.As(err, &statusErr) || statusErr.Code != status {
			t.Fatalf("HTTP %d lost typed status: %v", status, err)
		}
		if strings.Contains(err.Error(), "secret-sentinel") || strings.Contains(err.Error(), "/admin/") {
			t.Fatalf("native diagnostics escaped: %v", err)
		}
		if IsNotFound(err) != (status == http.StatusNotFound) || IsForbidden(err) != (status == http.StatusForbidden) {
			t.Fatalf("wrong status classification: %v", err)
		}
	}
	if IsNotFound(errors.New("untrusted body 404: not proof")) || IsForbidden(errors.New("untrusted body 403: not proof")) {
		t.Fatal("arbitrary error string forged HTTP status")
	}
	kc := New("https://keycloak.invalid", "operator", "fixture")
	kc.token = "fixture"
	kc.tokenExpiry = time.Now().Add(time.Hour)
	kc.httpClient = &http.Client{Transport: responseRoundTripper(func(*http.Request) (*http.Response, error) { return nil, fmt.Errorf("secret-sentinel transport") })}
	_, err := kc.ListRealms(context.Background())
	if !errors.Is(err, ErrTransport) || strings.Contains(err.Error(), "secret-sentinel") {
		t.Fatalf("transport diagnostics escaped: %v", err)
	}
}
func TestKeycloakGatewaySuppressesNativeErrorBodyBeforeAnyCaller(t *testing.T) {
	response, err := boundedKeycloakResponse(&http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader("secret-sentinel")), ContentLength: -1}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if strings.Contains(string(body), "secret-sentinel") {
		t.Fatal("native body escaped gateway")
	}
}

func TestTLSVerificationKeepsTypedCategoryWithoutNativeCertificateDetails(t *testing.T) {
	native := &tls.CertificateVerificationError{Err: errors.New("secret-sentinel certificate identity")}
	err := safeTransportError(fmt.Errorf("transport URL secret-sentinel: %w", native))
	if !errors.Is(err, ErrTransport) || !errors.Is(err, ErrTLSVerification) {
		t.Fatal("TLS verification category lost")
	}
	if strings.Contains(err.Error(), "secret-sentinel") {
		t.Fatal("native transport detail leaked")
	}
	var leaked *tls.CertificateVerificationError
	if errors.As(err, &leaked) {
		t.Fatal("native transport diagnostics retained in public error chain")
	}
	if errors.Is(safeTransportError(errors.New("secret-sentinel")), ErrTLSVerification) {
		t.Fatal("arbitrary transport failure forged TLS verification")
	}
}
