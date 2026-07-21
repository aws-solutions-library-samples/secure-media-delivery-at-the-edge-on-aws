variable "account_id" {
  type        = string
  description = "Target AWS account id. Guards against workspace/tfvars mismatch."
  nullable    = false
}

variable "region" {
  type        = string
  description = "AWS region for all resources."
  default     = "us-east-1"
  nullable    = false
}

variable "environment" {
  type        = string
  description = "Deployment environment (nfhs-staging | nfhs-prod)."
  nullable    = false
}

variable "name_prefix" {
  type        = string
  description = "Prefix for named resources (function, key group, WebACL, etc.)."
  default     = "cta-secure-media"
  nullable    = false
}

variable "signing_key_length" {
  type        = number
  description = "HMAC signing key length. 64 matches the CDK reference solution."
  default     = 64
  nullable    = false
}

variable "rotation_schedule" {
  type        = string
  description = "EventBridge schedule expression for the signing-key rotation Step Function. Default matches the CDK stack's 30-day cadence."
  default     = "rate(30 days)"
  nullable    = false
}

variable "demo_origin_domain" {
  type        = string
  description = "Default-behavior origin domain. Stage default matches the CDK reference solution's demo playback host. Override in prod tfvars to point at real content origin."
  default     = "cdn.mediaplaypen.com"
  nullable    = false
}

# VID-3449: gate POST /api/token to IAM-authenticated callers so the only
# way to mint a CWT is through drm-api-lambda (which does entitlement
# checks against member-service). Anonymous callers hit 403 at APIGW.
#
# Empty string keeps the reference-solution behavior (authorization = NONE,
# anyone can mint). Set to the drm-api-lambda execution role ARN in envs
# that participate in the CTA-5007-B rollout; the REST API resource policy
# then restricts invoke to that role alone.
variable "token_validation_enabled" {
  type        = bool
  description = "Master switch for CTA token validation at the edge. When false, the validator forwards every viewer request without inspecting the token — break-glass bypass for staged rollout or incident response. Baked into the CloudFront Function at deploy time; flipping requires a Terraform apply."
  default     = true
  nullable    = false
}

variable "geo_validation_enabled" {
  type        = bool
  description = "Enforce geo restrictions at the edge. When false, the catgeoiso3166 country claim is not checked (future zip/DMA edge checks per VID-3450 will live under the same flag). Other claim checks (URI/IP/exp/nbf/revocation) still run."
  default     = true
  nullable    = false
}

variable "drm_api_lambda_role_arn" {
  type        = string
  description = "ARN of the drm-api-lambda execution role. When non-empty, flips POST /api/token to AWS_IAM authorization and installs a resource policy allowing invoke only from this role."
  default     = ""
  nullable    = false
}
