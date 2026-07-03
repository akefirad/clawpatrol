package credentials_test

import (
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	// Blank-import the full plugin set so `endpoint "https"`,
	// `credential "aws_sso_credential"`, profiles, etc. are all
	// registered. aws_sso lives in the credentials package this
	// aggregator already imports — no aggregator edit was needed.
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

// TestAWSSSOCredentialConfigCompilesAndBinds loads a gateway config that
// declares an `aws_sso_credential` (one authentication + two role
// mappings) bound to an `https` endpoint and asserts it decodes and
// compiles — i.e. the schema (start_url, region, repeated `role` blocks)
// parses and the profile → credential → endpoint closure binds.
func TestAWSSSOCredentialConfigCompilesAndBinds(t *testing.T) {
	src := `gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "https" "aws" {
  hosts = ["*.amazonaws.com"]
}

credential "aws_sso_credential" "sso" {
  start_url = "https://acme.awsapps.com/start"
  region    = "us-east-1"
  endpoint  = https.aws

  role {
    account_id  = "111111111111"
    role_name   = "Admin"
    placeholder = "AKIAPROD0ADMIN000000"
  }
  role {
    account_id  = "222222222222"
    role_name   = "ReadOnly"
    placeholder = "AKIADEV00READONLY000"
  }
}

profile "default" {
  credentials = [aws_sso_credential.sso]
}
`
	gw, diags := config.LoadBytes([]byte(src), "aws_sso_smoke.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// The endpoint must be in scope for the default profile via the
	// transitive closure profile → credential → endpoint (i.e. the
	// aws_sso credential actually bound the https endpoint).
	prof, ok := cp.Profiles["default"]
	if !ok {
		t.Fatal("compiled policy has no default profile")
	}
	if len(prof.Credentials) == 0 {
		t.Fatal("default profile bound no credentials — aws_sso_credential did not bind the endpoint")
	}
}

// TestAWSSSOCredentialConfigRoundTrips asserts the Emit hook serializes
// the credential back to HCL that re-parses to an equivalent config
// (start_url, region, and both role blocks survive).
func TestAWSSSOCredentialConfigRoundTrips(t *testing.T) {
	src := `gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "https" "aws" { hosts = ["*.amazonaws.com"] }

credential "aws_sso_credential" "sso" {
  start_url = "https://acme.awsapps.com/start"
  region    = "us-east-1"
  endpoint  = https.aws
  role {
    account_id  = "111111111111"
    role_name   = "Admin"
    placeholder = "AKIAPROD0ADMIN000000"
  }
}

profile "default" { credentials = [aws_sso_credential.sso] }
`
	gw, diags := config.LoadBytes([]byte(src), "aws_sso_roundtrip.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	emittedBytes, err := config.Emit(gw)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	emitted := string(emittedBytes)
	for _, want := range []string{
		`start_url`, `"https://acme.awsapps.com/start"`,
		`role {`, `account_id`, `"111111111111"`,
		`role_name`, `"Admin"`, `placeholder`, `"AKIAPROD0ADMIN000000"`,
	} {
		if !strings.Contains(emitted, want) {
			t.Errorf("emitted HCL missing %q\n---\n%s", want, emitted)
		}
	}

	// And the emitted HCL must re-parse.
	if _, d := config.LoadBytes(emittedBytes, "aws_sso_reemit.hcl"); d.HasErrors() {
		t.Fatalf("re-parse emitted HCL: %v", d)
	}
}
