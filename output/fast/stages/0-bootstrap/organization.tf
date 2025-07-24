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

# tfdoc:file:description Organization-level IAM.

locals {
  # reassemble logical bindings into the formats expected by the module
  _iam_bindings = merge(
    local.iam_domain_bindings,
    local.iam_sa_bindings,
    local.iam_user_bootstrap_bindings,
    {
      for k, v in local.iam_principal_bindings : k => {
        authoritative = []
        additive      = v.additive
      }
    }
  )
  _iam_bindings_auth = flatten([
    for member, data in local._iam_bindings : [
      for role in data.authoritative : {
        member = member
        role   = role
      }
    ]
  ])
  _iam_bindings_add = flatten([
    for member, data in local._iam_bindings : [
      for role in data.additive : {
        member = member
        role   = role
      }
    ]
  ])
  org_policies_tag_name = "${var.organization.id}/${var.org_policies_config.tag_name}"
  iam_principals = {
    for k, v in local.iam_principal_bindings : k => v.authoritative
  }
  iam = merge(
    {
      for r in local.iam_delete_roles : r => []
    },
    {
      for b in local._iam_bindings_auth : b.role => b.member...
    }
  )
  iam_bindings_additive = {
    for b in local._iam_bindings_add : "${b.role}-${b.member}" => {
      member = b.member
      role   = b.role
    }
  }
  # Check if bootstrap_user comes from WIF
  bootstrap_principal = var.bootstrap_user == null ? null : (
    strcontains(var.bootstrap_user, ":")
    ? var.bootstrap_user
    : "user:${var.bootstrap_user}"
  )

  # Import default org-level org-policies
  org_policies_to_import = toset([
      "iam.disableServiceAccountKeyCreation",
      "iam.disableServiceAccountKeyUpload",
      "iam.automaticIamGrantsForDefaultServiceAccounts",
      "iam.allowedPolicyMemberDomains",
      "essentialcontacts.allowedContactDomains",
      "storage.uniformBucketLevelAccess",
      "compute.requireShieldedVm",
      "compute.trustedImageProjects",
      "compute.skipDefaultNetworkCreation",
      "container.clusterAutoupdateDefault",
      "container.clusterAutorepairDefault",
  ])
}

# Ensure that the logging service account is also added with the correct permissions
resource "google_project_iam_member" "log_writer" {
  project = "bootstrap-project-summit-25"
  role    = "roles/logging.logSinkWriter"
  member  = "serviceAccount:p134373643885-973186@gcp-sa-logging.iam.gserviceaccount.com"
}

resource "google_organization_iam_binding" "org_policies" {
  org_id = var.organization.id
  role   = "roles/orgpolicy.policyAdmin"
  members = [
    "group:gcp-organization-admins@example.org",
  ]
}

resource "google_project_service" "required_services" {
  project = "bootstrap-project-summit-25"
  service = "containeranalysis.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "asset_inventory" {
  project = "bootstrap-project-summit-25"
  service = "cloudasset.googleapis.com"
  disable_on_destroy = false
}

resource "google_logging_metric" "audit_configuration_changes" {
  name = "audit-configuration-changes"
  project = "bootstrap-project-summit-25"
  description = "Metric for audit configuration changes"
  filter = "logName:\"projects/YOUR_PROJECT_ID/logs/cloudaudit.googleapis.com%2Factivity\" OR logName:\"projects/YOUR_PROJECT_ID/logs/cloudaudit.googleapis.com%2Fsystem_event\" OR logName:\"projects/YOUR_PROJECT_ID/logs/cloudaudit.googleapis.com%2Fpolicy\" OR logName:\"projects/YOUR_PROJECT_ID/logs/cloudaudit.googleapis.com%2Faccess_transparency\""
  metric_descriptor {
    name = "logging.googleapis.com/user_defined/audit_configuration_changes"
    type = "GAUGE"
    metric_kind = "GAUGE"
    value_type = "INT64"
    unit = "1"
  }
}

resource "google_monitoring_alert_policy" "audit_configuration_changes_alert" {
  project = "bootstrap-project-summit-25"
  display_name = "Alert for Audit Configuration Changes"
  combiner = "OR"
  enabled = true
  notification_channels = []

  conditions {
    display_name = "Condition for Audit Configuration Changes"
    condition_threshold {
      filter = "metric.type = \"logging.googleapis.com/user_defined/audit_configuration_changes\" AND resource.project_id = \"YOUR_PROJECT_ID\""
      duration = "300s"
      comparison = "COMPARISON_GT"
      threshold_value = 0
      trigger {
        count = 1
      }
    }
  }
}

resource "google_logging_metric" "bucket_permission_changes" {
  name = "bucket-permission-changes"
  project = "bootstrap-project-summit-25"
  description = "Metric for Cloud Storage IAM Permission Changes"
  filter = "logName:\"projects/YOUR_PROJECT_ID/logs/cloudaudit.googleapis.com%2Fdata_access\" AND protoPayload.serviceName=\"storage.googleapis.com\" AND protoPayload.methodName:(\"storage.setIamPermissions\" OR \"storage.updateBucket\")"
  metric_descriptor {
    name = "logging.googleapis.com/user_defined/bucket_permission_changes"
    type = "GAUGE"
    metric_kind = "GAUGE"
    value_type = "INT64"
    unit = "1"
  }
}

resource "google_monitoring_alert_policy" "bucket_permission_changes_alert" {
  project = "bootstrap-project-summit-25"
  display_name = "Alert for Cloud Storage IAM Permission Changes"
  combiner = "OR"
  enabled = true
  notification_channels = []

  conditions {
    display_name = "Condition for Bucket Permission Changes"
    condition_threshold {
      filter = "metric.type = \"logging.googleapis.com/user_defined/bucket_permission_changes\" AND resource.project_id = \"YOUR_PROJECT_ID\""
      duration = "300s"
      comparison = "COMPARISON_GT"
      threshold_value = 0
      trigger {
        count = 1
      }
    }
  }
}

resource "google_logging_metric" "project_ownership_changes" {
  name = "project-ownership-changes"
  project = "bootstrap-project-summit-25"
  description = "Metric for Project Ownership Assignments/Changes"
  filter = "logName:\"projects/YOUR_PROJECT_ID/logs/cloudaudit.googleapis.com%2Factivity\" AND protoPayload.methodName=\"SetIamPolicy\" AND protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\""
  metric_descriptor {
    name = "logging.googleapis.com/user_defined/project_ownership_changes"
    type = "GAUGE"
    metric_kind = "GAUGE"
    value_type = "INT64"
    unit = "1"
  }
}

resource "google_monitoring_alert_policy" "project_ownership_changes_alert" {
  project = "bootstrap-project-summit-25"
  display_name = "Alert for Project Ownership Changes"
  combiner = "OR"
  enabled = true
  notification_channels = []

  conditions {
    display_name = "Condition for Project Ownership Changes"
    condition_threshold {
      filter = "metric.type = \"logging.googleapis.com/user_defined/project_ownership_changes\" AND resource.project_id = \"YOUR_PROJECT_ID\""
      duration = "300s"
      comparison = "COMPARISON_GT"
      threshold_value = 0
      trigger {
        count = 1
      }
    }
  }
}

resource "google_logging_metric" "sql_instance_configuration_changes" {
  name = "sql-instance-configuration-changes"
  project = "bootstrap-project-summit-25"
  description = "Metric for SQL Instance Configuration Changes"
  filter = "logName:\"projects/YOUR_PROJECT_ID/logs/cloudaudit.googleapis.com%2Fdata_access\" AND protoPayload.serviceName=\"sqladmin.googleapis.com\" AND protoPayload.methodName:\"cloudsql.instances.update\""
  metric_descriptor {
    name = "logging.googleapis.com/user_defined/sql_instance_configuration_changes"
    type = "GAUGE"
    metric_kind = "GAUGE"
    value_type = "INT64"
    unit = "1"
  }
}

resource "google_monitoring_alert_policy" "sql_instance_configuration_changes_alert" {
  project = "bootstrap-project-summit-25"
  display_name = "Alert for SQL Instance Configuration Changes"
  combiner = "OR"
  enabled = true
  notification_channels = []

  conditions {
    display_name = "Condition for SQL Instance Configuration Changes"
    condition_threshold {
      filter = "metric.type = \"logging.googleapis.com/user_defined/sql_instance_configuration_changes\" AND resource.project_id = \"YOUR_PROJECT_ID\""
      duration = "300s"
      comparison = "COMPARISON_GT"
      threshold_value = 0
      trigger {
        count = 1
      }
    }
  }
}
