# AWS IAM Identity Center (SSO), multi-account / multi-role.
#
# One dashboard device login (the aws_sso_credential's "Connect" card)
# fans out to many (account, role) mappings. The agent picks a role per
# request with the standard AWS_PROFILE / --profile: each profile carries
# a distinct PLACEHOLDER access-key-id; the gateway maps that placeholder to
# the role's real, short-lived credentials (minted + cached via
# sso:GetRoleCredentials) and re-signs the request. The agent never holds
# real credentials. A call with no matching placeholder is NOT re-signed by
# the gateway: it forwards upstream still carrying the agent's placeholder
# signature, which AWS rejects (InvalidClientTokenId) — so it's effectively
# denied, but by AWS, not by a gateway-level block.
#
# AGENT PROFILES ARE NOT WRITTEN BY CLAWPATROL. This credential does no env
# pushdown; you must hand-author the agent's ~/.aws/credentials, one profile
# per role, each with that role's placeholder as aws_access_key_id and a
# throwaway 40-char secret (aws-cli needs 40 chars to sign LOCALLY; the
# gateway discards it and re-signs). Example, matching the roles below:
#
#     # ~/.aws/credentials  (on the agent)
#     [readonly]
#     aws_access_key_id     = AKIACLAWPATROLRO0000
#     aws_secret_access_key = clawpatrolPlaceholderSecretDoNotUse00000
#     [admin]
#     aws_access_key_id     = AKIACLAWPATROLADMIN0
#     aws_secret_access_key = clawpatrolPlaceholderSecretDoNotUse00000
#
# The aws_access_key_id MUST equal the role's `placeholder` here. NOTE:
# GitHub secret scanning flags the AKIA[0-9A-Z]{16} shape, so committing an
# agent config with these placeholders may trip scanners (arguably a feature
# — but expect the alert; the secret is a throwaway, not a real key).
#
# POLICY is stock http-facet rules on the reused `https` endpoint(s) — no
# AWS-specific policy engine. The http facet exposes no host, so to gate a
# SPECIFIC service (e.g. S3) give it its own endpoint (host-matched) and
# attach rules there. JSON-protocol services (DynamoDB, ...) put the IAM
# action in the X-Amz-Target header as "<Service>.<Action>", so they can be
# gated by header instead.
#
# !!! POLICY CAVEAT — ROLE SELECTION IS INVISIBLE TO THE RULES ENGINE !!!
# The rules see method/path/query/headers/body, NOT the matched (account,
# role). So every role on ONE credential shares ONE policy surface: an
# endpoint's rules are the UNION across all its roles. In the example below,
# a GET allowed by `aws-reads` is allowed no matter WHICH placeholder the
# agent signed with — ReadOnly or Admin. An agent that passes the shared
# rules can always mint the most privileged configured role.
#   => Isolate a high-privilege role: put it on its OWN aws_sso_credential
#      bound to its OWN endpoint, and attach the stricter rules there. Do NOT
#      mix a privileged role with low-privilege ones on a shared endpoint
#      (as ReadOnly + Admin are mixed below purely to show the mechanics).
# IMPROVEMENT: expose the matched (account, role) to CEL — a policy-visible
# field, or per-role endpoint bindings — so rules can discriminate per role
# instead of per shared endpoint. Deferred (touches the facet/policy engine,
# not just this plugin).

credential "aws_sso_credential" "sso" {
  start_url = "https://my-org.awsapps.com/start"
  region    = "us-east-1"
  endpoints = [https.aws, https.aws-s3]

  role {
    account_id  = "111111111111"
    role_name   = "ReadOnly"
    placeholder = "AKIACLAWPATROLRO0000"
  }
  role {
    account_id  = "222222222222"
    role_name   = "Admin"
    placeholder = "AKIACLAWPATROLADMIN0"
  }
}

# S3 on its own endpoint so its writes can be gated by HTTP method (S3 is
# a REST API: GET/HEAD = read, PUT/POST/DELETE = write). These suffixes are
# longer than the catch-all `*.amazonaws.com` on `https.aws`, so S3 hosts
# route here (longest matching suffix wins). Host patterns allow a single
# `*`, so add a `*.s3.<region>.amazonaws.com` entry per region you use
# (e.g. "*.s3.us-east-1.amazonaws.com") alongside the global ones below.
endpoint "https" "aws-s3" {
  hosts = ["*.s3.amazonaws.com", "s3.amazonaws.com"]
}

# Everything else in AWS.
endpoint "https" "aws" {
  hosts = ["*.amazonaws.com"]
}

# ── S3 policy: reads allowed, writes require human approval ───────────
rule "s3-reads" {
  endpoint  = https.aws-s3
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}
rule "s3-writes-approve" {
  endpoint  = https.aws-s3
  condition = "http.method in ['PUT', 'POST', 'DELETE']"
  approve   = [human_approver.ops]
}
# In-scope HTTPS rules fail OPEN on no-match, so a lowest-priority
# catch-all deny is mandatory.
rule "s3-default-deny" {
  endpoint = https.aws-s3
  priority = -100
  verdict  = "deny"
  reason   = "S3: verb not allowed by policy"
}

# ── General AWS policy: reads allowed; a JSON-service write gate ──────
rule "aws-reads" {
  endpoint  = https.aws
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}
# JSON-protocol services carry the IAM action in X-Amz-Target — here,
# require human approval for DynamoDB item writes. The `in` guard keeps a
# request without the header from erroring (it just won't match).
rule "aws-dynamodb-writes-approve" {
  endpoint  = https.aws
  condition = <<-CEL
    'X-Amz-Target' in http.headers &&
    http.headers['X-Amz-Target'].exists(t,
      t.contains('DynamoDB_') && (
        t.endsWith('.PutItem') || t.endsWith('.UpdateItem') ||
        t.endsWith('.DeleteItem') || t.endsWith('.BatchWriteItem')))
  CEL
  approve = [human_approver.ops]
}
rule "aws-default-deny" {
  endpoint = https.aws
  priority = -100
  verdict  = "deny"
  reason   = "AWS: not allowed by policy"
}

# ===== harness =====

gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

credential "slack_tokens" "slack-bot" {}

approver "human_approver" "ops" {
  channel    = "#agent-ops"
  credential = slack_tokens.slack-bot
  timeout    = 600
}

profile "default" { credentials = [aws_sso_credential.sso] }
