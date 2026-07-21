# CTA-5007-B secure media delivery — Terraform port of source/lib/cta-secure-media-stack.ts.
#
# See terraform/README.md for the resource inventory + what's ported vs
# still remaining. VID-3439.

locals {
  account_id  = var.account_id
  region      = var.region
  environment = var.environment
  name_prefix = var.name_prefix

  # Short env slug for names that don't tolerate the full "nfhs-staging".
  env_slug = replace(var.environment, "nfhs-", "")

  # Belt-and-braces: assert the workspace / tfvars was pointed at the
  # right account before letting apply run.
  _account_check = data.aws_caller_identity.current.account_id == var.account_id ? "" : file("ERROR: caller account ${data.aws_caller_identity.current.account_id} does not match var.account_id ${var.account_id}")
}

# --------------------------------------------------------------------------
# CloudFront KeyValueStore — holds the signing key + revocation list.
#
# Fresh KVS on this cutover (per Will's call): stage tokens minted against
# the CDK stack become invalid, clients re-mint on next request. Prod
# cutover (out of scope for this ticket) will need import + coordination.
# --------------------------------------------------------------------------
resource "aws_cloudfront_key_value_store" "this" {
  name    = "${local.name_prefix}-${local.env_slug}"
  comment = "CTA-5007-B signing key + revocation list. VID-3439."
}

# --------------------------------------------------------------------------
# Secrets Manager — HMAC signing key.
#
# aws_secretsmanager_secret + aws_secretsmanager_secret_version generate the
# key on first apply; the plaintext value is held in Terraform state (see
# README security section). Rotation is driven by the Step Functions
# workflow in rotation.tf on the schedule set by var.rotation_schedule.
# --------------------------------------------------------------------------
resource "random_password" "signing_key" {
  length  = var.signing_key_length
  special = false
}

resource "aws_secretsmanager_secret" "signing_key" {
  name        = "${local.name_prefix}/${local.env_slug}/signing-key"
  description = "CTA-5007-B HMAC signing key. VID-3439."

  # Match CDK stack's removal semantics — stage can be destroyed clean.
  recovery_window_in_days = local.environment == "nfhs-prod" ? 30 : 0
}

resource "aws_secretsmanager_secret_version" "signing_key" {
  secret_id = aws_secretsmanager_secret.signing_key.id
  secret_string = jsonencode({
    algorithm  = "HMAC-SHA256"
    signingKey = random_password.signing_key.result
  })
}

# --------------------------------------------------------------------------
# CloudFront Function — CTA validator.
#
# JS source lives at ../source/lambda/cta_token_validator.js (CDK
# app's convention — everything under source/). Once VID-3439's port
# is complete and source/ is deleted, move lambda*/ up one level and
# update this path.
#
# In-repo reference means no drift with the SDK code the Lambdas use
# (../source/lambda/sdk/cta-client.js), which is the important invariant.
#
# Consumers (e.g. hls.bcast.stage in playon/iac-tf-aws-project-video-common)
# reference this function by ARN via aws_cloudfront_function's function_arn
# output. Cross-repo coupling is one ARN string.
# --------------------------------------------------------------------------
resource "aws_cloudfront_function" "validator" {
  name    = "${local.name_prefix}-${local.env_slug}-validator"
  runtime = "cloudfront-js-2.0"
  comment = "CTA-5007-B CWT validator. VID-3439."
  publish = true
  code = templatefile("${path.module}/../source/lambda/cta_token_validator.js.tftpl", {
    token_validation_enabled = var.token_validation_enabled ? "true" : "false"
    geo_validation_enabled   = var.geo_validation_enabled ? "true" : "false"
  })

  key_value_store_associations = [aws_cloudfront_key_value_store.this.arn]
}
