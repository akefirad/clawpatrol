package endpoints

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"

	"github.com/denoland/clawpatrol/internal/config"
)

// TestKubernetesEndpointConfigureUpstreamTLS verifies the endpoint's
// ca_cert HCL field is applied to cfg.RootCAs at dial time. Without
// this wiring the EKS apiserver path errors with "x509: certificate
// signed by unknown authority" because EKS uses a per-cluster CA
// that no system trust store carries.
func TestKubernetesEndpointConfigureUpstreamTLS(t *testing.T) {
	// Real self-signed ed25519 cert (generated once with `openssl req`),
	// included verbatim so the test stays hermetic.
	const ca = `-----BEGIN CERTIFICATE-----
MIIBTzCCAQGgAwIBAgIUIFiZ5s2fC7N/ElT4ljred+5VuZYwBQYDK2VwMB0xGzAZ
BgNVBAMMEmNsYXdwYXRyb2wtdGVzdC1jYTAeFw0yNjA1MTMyMjM2MDdaFw0zNjA1
MTAyMjM2MDdaMB0xGzAZBgNVBAMMEmNsYXdwYXRyb2wtdGVzdC1jYTAqMAUGAytl
cAMhAEEjAD+PAfsebOa0TpxGWC4BbXTJZS0Zyio+ag4KjFuMo1MwUTAdBgNVHQ4E
FgQUyuf5UybO1z6734KuSwqtX94QnmQwHwYDVR0jBBgwFoAUyuf5UybO1z6734Ku
SwqtX94QnmQwDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQA4uIgKBvkbVsXIoitq
DpvHwDcxnGIz9Te9sfFH29Zr2iHwmMcz5T34iFfm/7XpBw8ajzrO+i5nFfIofiAI
bRYL
-----END CERTIFICATE-----`
	e := &KubernetesEndpoint{CACert: ca}
	cfg := &tls.Config{}
	if err := e.ConfigureUpstreamTLS(cfg); err != nil {
		t.Fatalf("ConfigureUpstreamTLS: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs is nil after ConfigureUpstreamTLS — ca_cert was ignored")
	}
	if got := len(cfg.RootCAs.Subjects()); got == 0 { //nolint:staticcheck // SA1019 fine for test
		t.Fatal("RootCAs has no certificates after ConfigureUpstreamTLS")
	}
}

// TestKubernetesEndpointConfigureUpstreamTLSEmpty verifies the
// no-op path: endpoints that don't declare a ca_cert leave cfg
// untouched so the credential's ConfigureUpstreamTLS (mtls) or the
// system trust store still wins.
func TestKubernetesEndpointConfigureUpstreamTLSEmpty(t *testing.T) {
	e := &KubernetesEndpoint{}
	cfg := &tls.Config{}
	if err := e.ConfigureUpstreamTLS(cfg); err != nil {
		t.Fatalf("ConfigureUpstreamTLS: %v", err)
	}
	if cfg.RootCAs != nil {
		t.Fatal("RootCAs mutated even though ca_cert was empty")
	}
}

// TestKubernetesEndpointConfigureUpstreamTLSBadPEM surfaces a
// configuration error when ca_cert isn't decodable. Operators see
// the error at dial time (logged + fallback to default roots).
func TestKubernetesEndpointConfigureUpstreamTLSBadPEM(t *testing.T) {
	e := &KubernetesEndpoint{CACert: "not a pem"}
	cfg := &tls.Config{}
	err := e.ConfigureUpstreamTLS(cfg)
	if err == nil {
		t.Fatal("expected error on un-decodable ca_cert")
	}
	if !strings.Contains(err.Error(), "PEM") {
		t.Errorf("err = %v, want one mentioning PEM", err)
	}
}

// TestValidateKubernetesEndpointEKSSSOParams pins the load-time
// validation of the aws_sso_eks_credential auth params: account_id must
// be 12 digits, account_id/role_name are a neither-or-both pair, and
// either requires cluster_name + region. Misconfig should surface as a
// load diagnostic, not a request-time (unauthenticated) apiserver call.
func TestValidateKubernetesEndpointEKSSSOParams(t *testing.T) {
	cases := []struct {
		name    string
		ep      *KubernetesEndpoint
		wantErr string // substring; "" means load must succeed
	}{
		{
			name: "valid full sso pair",
			ep:   &KubernetesEndpoint{Hosts: []string{"eks.example"}, ClusterName: "c", Region: "us-west-2", AccountID: "123456789012", RoleName: "EKSAdmin"},
		},
		{
			name: "no sso params (plain eks / self-hosted)",
			ep:   &KubernetesEndpoint{Hosts: []string{"eks.example"}, ClusterName: "c", Region: "us-west-2"},
		},
		{
			name:    "account without role",
			ep:      &KubernetesEndpoint{Hosts: []string{"eks.example"}, ClusterName: "c", Region: "us-west-2", AccountID: "123456789012"},
			wantErr: "set together",
		},
		{
			name:    "role without account",
			ep:      &KubernetesEndpoint{Hosts: []string{"eks.example"}, ClusterName: "c", Region: "us-west-2", RoleName: "EKSAdmin"},
			wantErr: "set together",
		},
		{
			name:    "account id too short",
			ep:      &KubernetesEndpoint{Hosts: []string{"eks.example"}, ClusterName: "c", Region: "us-west-2", AccountID: "12345", RoleName: "EKSAdmin"},
			wantErr: "12 digits",
		},
		{
			name:    "account id non-numeric",
			ep:      &KubernetesEndpoint{Hosts: []string{"eks.example"}, ClusterName: "c", Region: "us-west-2", AccountID: "12345678901x", RoleName: "EKSAdmin"},
			wantErr: "12 digits",
		},
		{
			name:    "sso pair without cluster_name",
			ep:      &KubernetesEndpoint{Hosts: []string{"eks.example"}, Region: "us-west-2", AccountID: "123456789012", RoleName: "EKSAdmin"},
			wantErr: "cluster_name and region are required",
		},
		{
			name:    "sso pair without region",
			ep:      &KubernetesEndpoint{Hosts: []string{"eks.example"}, ClusterName: "c", AccountID: "123456789012", RoleName: "EKSAdmin"},
			wantErr: "cluster_name and region are required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			diags := validateKubernetesEndpoint(tc.ep, "k8s-test", &config.BuildCtx{Block: &hcl.Block{}})
			if tc.wantErr == "" {
				if diags.HasErrors() {
					t.Fatalf("unexpected diagnostics: %s", diags.Error())
				}
				return
			}
			if !diags.HasErrors() {
				t.Fatalf("expected error mentioning %q, got none", tc.wantErr)
			}
			if !strings.Contains(diags.Error(), tc.wantErr) {
				t.Errorf("diagnostics = %q, want substring %q", diags.Error(), tc.wantErr)
			}
		})
	}
}
