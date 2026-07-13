# Exercises the aws_sso_eks_credential + the kubernetes endpoint's
# account_id / role_name extension: one AWS SSO session minting EKS
# API-server bearers for a cluster whose SSO role is selected by
# (account_id, role_name). Pins the required-attr load (start_url,
# region) and the Emit round-trip of the new endpoint fields with
# NON-empty values.
#
# Also pins the session-reuse path: a second EKS credential sets
# `session = "corp-sso"` (instead of start_url) to reuse the first
# credential's AWS SSO login rather than prompting a second device
# login. This covers the nil-OAuthFlow branch, the session Emit
# round-trip, and the session-only load (no start_url).

gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

defaults {
  unknown_host  = "passthrough"
  llm_fail_mode = "closed"
}

# EKS cluster reached via an AWS SSO session. cluster_name + region
# scope the STS presign; account_id + role_name select the SSO role the
# credential assumes for this cluster. One SSO credential can serve many
# such clusters/accounts.
endpoint "kubernetes" "eks-corp-prod" {
  hosts        = ["*.gr7.us-east-2.eks.amazonaws.com"]
  cluster_name = "corp-prod"
  region       = "us-east-2"
  account_id   = "123456789012"
  role_name    = "EKSAdmin"
}

# The SSO session. start_url + region drive the aws_sso device flow; the
# region here is the SSO portal region, independent of the cluster
# region on the endpoint above.
credential "aws_sso_eks_credential" "corp-sso" {
  endpoint  = kubernetes.eks-corp-prod
  start_url = "https://my-org.awsapps.com/start"
  region    = "eu-central-1"
}

# A second EKS cluster in a different account/role, reached with the SAME
# AWS SSO login as corp-sso.
endpoint "kubernetes" "eks-corp-staging" {
  hosts        = ["*.gr7.us-west-2.eks.amazonaws.com"]
  cluster_name = "corp-staging"
  region       = "us-west-2"
  account_id   = "210987654321"
  role_name    = "EKSReadOnly"
}

# Session reuse: no start_url of its own — `session` names corp-sso, so
# this credential borrows corp-sso's SSO session (one device login serves
# both). region is still required (it scopes sso:GetRoleCredentials).
credential "aws_sso_eks_credential" "staging-sso" {
  endpoint = kubernetes.eks-corp-staging
  session  = "corp-sso"
  region   = "eu-central-1"
}

rule "eks-reads" {
  endpoint  = kubernetes.eks-corp-prod
  condition = "k8s.verb in ['get', 'list', 'watch']"
  verdict   = "allow"
}

rule "eks-default" {
  endpoint = kubernetes.eks-corp-prod
  verdict  = "deny"
}

rule "eks-staging-reads" {
  endpoint  = kubernetes.eks-corp-staging
  condition = "k8s.verb in ['get', 'list', 'watch']"
  verdict   = "allow"
}

rule "eks-staging-default" {
  endpoint = kubernetes.eks-corp-staging
  verdict  = "deny"
}

profile "default" {
  credentials = [
    aws_sso_eks_credential.corp-sso,
    aws_sso_eks_credential.staging-sso,
  ]
}
