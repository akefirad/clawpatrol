package credentials

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// roleFixture is a single seeded role mapping used across the tests.
func ssoCredFixture() *AWSSSOCredential {
	return &AWSSSOCredential{
		StartURL: "https://acme.awsapps.com/start",
		Region:   "us-east-1",
		Roles: []AWSSSORole{
			{AccountID: "111111111111", RoleName: "Admin", Placeholder: "AKIAPROD0ADMIN000000"},
		},
	}
}

// seededSecret carries the (slice-1) "real" creds the gateway re-signs with.
func seededSecret() runtime.Secret {
	return runtime.Secret{Extras: map[string]string{
		"access_key_id":     "AKIDEXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}}
}

// signedReq builds a request the agent's aws-cli would have signed with
// the given placeholder access-key-id (scope names the real service +
// region, exactly as botocore emits).
func signedReq(t *testing.T, placeholderAKID string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("POST", "https://dynamodb.eu-west-1.amazonaws.com/", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+placeholderAKID+
		"/20260609/us-west-2/dynamodb/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=deadbeef")
	req.Header.Set("X-Amz-Content-Sha256", "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")
	return req
}

// TestAWSSSOCredentialReSignsSelectedRole verifies the credential
// self-dispatches on the placeholder access-key-id, matches the role
// mapping, and re-signs the request with the (seeded) real creds — the
// client's placeholder signature is replaced and the credential scope
// from the incoming header is preserved.
func TestAWSSSOCredentialReSignsSelectedRole(t *testing.T) {
	c := ssoCredFixture()
	req := signedReq(t, "AKIAPROD0ADMIN000000")

	if err := c.SignHTTPRequest(context.Background(), req, seededSecret(), struct{}{}); err != nil {
		t.Fatalf("sign: %v", err)
	}

	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("Authorization = %q, want a fresh SigV4 signature", auth)
	}
	if strings.Contains(auth, "deadbeef") {
		t.Errorf("Authorization still carries the client placeholder signature: %q", auth)
	}
	if !strings.Contains(auth, "Credential=AKIDEXAMPLE/") {
		t.Errorf("Authorization = %q, want re-signed with the seeded key AKIDEXAMPLE", auth)
	}
	if !strings.Contains(auth, "/us-west-2/dynamodb/aws4_request") {
		t.Errorf("Authorization = %q, want the scope from the incoming header (us-west-2/dynamodb)", auth)
	}
}

// TestAWSSSOCredentialUnknownPlaceholderFailsClosed verifies a request
// whose placeholder matches no role mapping is rejected and left
// un-re-signed (fail closed — no signing under an unintended identity).
func TestAWSSSOCredentialUnknownPlaceholderFailsClosed(t *testing.T) {
	c := ssoCredFixture()
	req := signedReq(t, "AKIAUNKNOWN000000000")

	err := c.SignHTTPRequest(context.Background(), req, seededSecret(), struct{}{})
	if err == nil {
		t.Fatal("expected an error for an unmatched placeholder access-key-id")
	}
	if !strings.Contains(err.Error(), "no role mapping") {
		t.Errorf("err = %v, want one mentioning the missing role mapping", err)
	}
	if auth := req.Header.Get("Authorization"); !strings.Contains(auth, "deadbeef") {
		t.Errorf("request was re-signed despite no matching role; Authorization = %q", auth)
	}
}

// TestAWSSSOCredentialNoSigV4Errors verifies a request without a parseable
// SigV4 access-key-id is rejected (nothing to route on).
func TestAWSSSOCredentialNoSigV4Errors(t *testing.T) {
	c := ssoCredFixture()
	req, err := http.NewRequest("GET", "https://dynamodb.eu-west-1.amazonaws.com/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := c.SignHTTPRequest(context.Background(), req, seededSecret(), struct{}{}); err == nil {
		t.Fatal("expected an error when the request carries no SigV4 access-key-id")
	}
}

func TestSigV4AccessKeyID(t *testing.T) {
	cases := []struct {
		name, header, want string
	}{
		{"well-formed", "AWS4-HMAC-SHA256 Credential=AKIAPROD0ADMIN000000/20260609/ap-south-1/s3/aws4_request, SignedHeaders=host, Signature=abc", "AKIAPROD0ADMIN000000"},
		{"missing", "Bearer something", ""},
		{"truncated scope", "AWS4-HMAC-SHA256 Credential=AKID/20260609/s3, SignedHeaders=host", ""},
		{"not aws4_request", "AWS4-HMAC-SHA256 Credential=AKID/20260609/ap-south-1/s3/v2_request, Signature=abc", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sigV4AccessKeyID(tc.header); got != tc.want {
				t.Errorf("sigV4AccessKeyID(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

func TestAWSSSORoleForPlaceholder(t *testing.T) {
	c := &AWSSSOCredential{Roles: []AWSSSORole{
		{AccountID: "111111111111", RoleName: "Admin", Placeholder: "AKIAPROD0ADMIN000000"},
		{AccountID: "222222222222", RoleName: "ReadOnly", Placeholder: "AKIADEV00READONLY000"},
	}}
	if r := c.roleForPlaceholder("AKIADEV00READONLY000"); r == nil || r.RoleName != "ReadOnly" {
		t.Errorf("roleForPlaceholder(dev) = %+v, want the ReadOnly role", r)
	}
	if r := c.roleForPlaceholder("AKIANOPE000000000000"); r != nil {
		t.Errorf("roleForPlaceholder(unknown) = %+v, want nil", r)
	}
	if r := c.roleForPlaceholder(""); r != nil {
		t.Errorf("roleForPlaceholder(empty) = %+v, want nil (empty must not match empty placeholder)", r)
	}
}
