/**
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

variable "billing_account" {
  description = "Billing account id. If billing account is not part of the same org set `is_org_level` to `false`. To disable handling of billing IAM roles set `no_iam` to `true`."
  type = object({
    id = string
    force_create = optional(object({
      dataset = optional(bool, false)
      project = optional(bool, false)
    }), {})
    is_org_level = optional(bool, true)
    no_iam       = optional(bool, false)
  })
  nullable = false
  validation {
    condition = (
      var.billing_account.force_create.dataset != true ||
      var.billing_account.force_create.project == true
    )
    error_message = "Forced dataset creation also needs project creation."
  }
}

variable "bootstrap_user" {
  description = "Email of the nominal user running this stage for the first time."
  type        = string
  default     = null
}

variable "cicd_config" {
  description = "CI/CD repository configuration. Identity providers reference keys in the `federated_identity_providers` variable. Set to null to disable, or set individual repositories to null if not needed."
  type = object({
    bootstrap = optional(object({
      identity_provider = string
      repository = object({
        name   = string
        branch = optional(string)
        type   = optional(string, "github")
      })
    }))
    resman = optional(object({
      identity_provider = string
      repository = object({
        name   = string
        branch = optional(string)
        type   = optional(string, "github")
      })
    }))
    vpcsc = optional(object({
      identity_provider = string
      repository = object({
        name   = string
        branch = optional(string)
        type   = optional(string, "github")
      })
    }))
  })
  nullable = false
  default  = {}
  validation {
    condition = alltrue([
      for k, v in coalesce(var.cicd_config, {}) :
      v == null || (
        contains(["github", "gitlab", "terraform"], coalesce(try(v.repository.type, null), "null"))
      )
    ])
    error_message = "Invalid repository type, supported types: 'github', 'gitlab', or 'terraform'."
  }
}

variable "custom_roles" {
  description = "Map of role names => list of permissions to additionally create at the organization level."
  type        = map(list(string))
  nullable    = false
  default     = {}
}

variable "environments" {
  description = "Environment names. When not defined, short name is set to the key and tag name to lower(name)."
  type = map(object({
    name       = string
    is_default = optional(bool, false)
    short_name = optional(string)
    tag_name   = optional(string)
  }))
  nullable = false
  default = {
    dev = {
      name = "Development"
    }
    prod = {
      name       = "Production"
      is_default = true
    }
  }
  validation {
    condition = anytrue([
      for k, v in var.environments : v.is_default == true
    ])
    error_message = "At least one environment should be marked as default."
  }
  validation {
    condition = alltrue([
      for k, v in var.environments : join(" ", regexall(
        "[a-zA-Z][a-zA-Z0-9\\s-]+[a-zA-Z0-9]", v.name
      )) == v.name
    ])
    error_message = "Environment names can only contain letters numbers dashes or spaces."
  }
  validation {
    condition = alltrue([
      for k, v in var.environments : (length(coalesce(v.short_name, k)) <= 4)
    ])
    error_message = "If environment key is longer than 4 characters, provide short_name that is at most 4 characters long."
  }
}

variable "essential_contacts" {
  description = "Email used for essential contacts, unset if null."
  type        = string
  default     = null
}

variable "factories_config" {
  description = "Configuration for the resource factories or external data."
  type = object({
    custom_constraints = optional(string, "data/custom-constraints")
    custom_roles       = optional(string, "data/custom-roles")
    org_policies       = optional(string, "data/org-policies")
    org_policies_iac   = optional(string, "data/org-policies-iac")
  })
  nullable = false
  default  = {}
}

variable "groups" {
  # https://cloud.google.com/docs/enterprise/setup-checklist
  description = "Group names or IAM-format principals to grant organization-level permissions. If just the name is provided, the 'group:' principal and organization domain are interpolated."
  type = object({
    gcp-billing-admins      = optional(string, "gcp-billing-admins")
    gcp-devops              = optional(string, "gcp-devops")
    gcp-network-admins      = optional(string, "gcp-vpc-network-admins")
    gcp-organization-admins = optional(string, "gcp-organization-admins")
    gcp-secops-admins       = optional(string, "gcp-security-admins")
    gcp-security-admins     = optional(string, "gcp-security-admins")
    # aliased to gcp-devops as the checklist does not create it
    gcp-support = optional(string, "gcp-devops")
  })
  nullable = false
  default  = {}
}

variable "iam" {
  description = "Organization-level custom IAM settings in role => [principal] format."
  type        = map(list(string))
  nullable    = false
  default     = {}
}

variable "iam_bindings_additive" {
  description = "Organization-level custom additive IAM bindings. Keys are arbitrary."
  type = map(object({
    member = string
    role   = string
    condition = optional(object({
      expression  = string
      title       = string
      description = optional(string)
    }))
  }))
  nullable = false
  default  = {}
}

variable "iam_by_principals" {
  description = "Authoritative IAM binding in {PRINCIPAL => [ROLES]} format. Principals need to be statically defined to avoid cycle errors. Merged internally with the `iam` variable."
  type        = map(list(string))
  default     = {}
  nullable    = false
}

variable "locations" {
  description = "Optional locations for GCS, BigQuery, and logging buckets created here."
  type = object({
    bq      = optional(string, "EU")
    gcs     = optional(string, "EU")
    logging = optional(string, "global")
    pubsub  = optional(list(string), [])
  })
  nullable = false
  default  = {}
}

variable "log_sinks" {
  description = "Org-level log sinks, in name => {type, filter} format."
  type = map(object({
    filter     = string
    type       = string
    disabled   = optional(bool, false)
    exclusions = optional(map(string), {})
  }))
  nullable = false
  default = {
    audit-logs = {
      # activity logs include Google Workspace / Cloud Identity logs
      # exclude them via additional filter stanza if needed
      filter = <<-FILTER
        log_id("cloudaudit.googleapis.com/activity") OR
        log_id("cloudaudit.googleapis.com/system_event") OR
        log_id("cloudaudit.googleapis.com/policy") OR
        log_id("cloudaudit.googleapis.com/access_transparency")
      FILTER
      type   = "logging"
      # exclusions = {
      #   gke-audit = "protoPayload.serviceName=\"k8s.io\""
      # }
    }
    iam = {
      filter = <<-FILTER
        protoPayload.serviceName="iamcredentials.googleapis.com" OR
        protoPayload.serviceName="iam.googleapis.com" OR
        protoPayload.serviceName="sts.googleapis.com"
      FILTER
      type   = "logging"
    }
    vpc-sc = {
      filter = <<-FILTER
        protoPayload.metadata.@type="type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata"
      FILTER
      type   = "logging"
    }
    workspace-audit-logs = {
      filter = <<-FILTER
        protoPayload.
