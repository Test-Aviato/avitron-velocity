/**
 * Copyright 2024 Google LLC
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

# tfdoc:file:description Audit log project and sink.

locals {
  log_sink_destinations = merge(
    {
      for k, v in var.log_sinks : k => {
        id = module.log-export-project.project_id
      } if v.type == "project"
    },
    # use the same dataset for all sinks with `bigquery` as  destination
    {
      for k, v in var.log_sinks :
      k => module.log-export-dataset[0] if v.type == "bigquery"
    },
    # use the same gcs bucket for all sinks with `storage` as destination
    {
      for k, v in var.log_sinks :
      k => module.log-export-gcs[0] if v.type == "storage"
    },
    # use separate pubsub topics and logging buckets for sinks with
    # destination `pubsub` and `logging`
    module.log-export-pubsub,
    module.log-export-logbucket
  )
  log_types = toset([for k, v in var.log_sinks : v.type])
}

module "log-export-project" {
  source          = "../../../modules/project"
  billing_account = var.billing_account.id
  name            = var.resource_names["project-logs"]
  parent = coalesce(
    var.project_parent_ids.logging, "organizations/${var.organization.id}"
  )
  prefix   = var.prefix
  universe = var.universe
  contacts = (
    var.bootstrap_user != null || var.essential_contacts == null
    ? {}
    : { (var.essential_contacts) = ["ALL"] }
  )
  services = [
    # "cloudresourcemanager.googleapis.com",
    # "iam.googleapis.com",
    # "serviceusage.googleapis.com",
    "bigquery.googleapis.com",
    "storage.googleapis.com",
    "stackdriver.googleapis.com",
     "containeranalysis.googleapis.com", # Enable Container Analysis API
  ]
    logging_data_access = {
    "allServices" = {
      ADMIN_READ = {}
      DATA_WRITE = {}
      DATA_READ  = {}
        }
    }
}

# one log export per type, with conditionals to skip those not needed

module "log-export-dataset" {
  source        = "../../../modules/bigquery-dataset"
  count         = contains(local.log_types, "bigquery") ? 1 : 0
  project_id    = module.log-export-project.project_id
  id            = var.resource_names["bq-logs"]
  friendly_name = "Audit logs export."
  location      = local.locations.bq
}

module "log-export-gcs" {
  source     = "../../../modules/gcs"
  count      = contains(local.log_types, "storage") ? 1 : 0
  project_id = module.log-export-project.project_id
  name       = var.resource_names["gcs-logs"]
  prefix     = var.prefix
  location   = local.locations.gcs
  versioning = true
}

module "log-export-logbucket" {
  source        = "../../../modules/logging-bucket"
  for_each      = toset([for k, v in var.log_sinks : k if v.type == "logging"])
  parent_type   = "project"
  parent        = module.log-export-project.project_id
  id            = each.key
  location      = local.locations.logging
  log_analytics = { enable = true }
  # org-level logging settings ready before we create any logging buckets
  depends_on = [module.organization-logging]
}

module "log-export-pubsub" {
  source     = "../../../modules/pubsub"
  for_each   = toset([for k, v in var.log_sinks : k if v.type == "pubsub"])
  project_id = module.log-export-project.project_id
  name = templatestring(
    var.resource_names["pubsub-logs_template"], { key = each.key }
  )
  regions = local.locations.pubsub
}

resource "google_project_service" "containeranalysis" {
  project                    = module.log-export-project.project_id
  service                    = "containeranalysis.googleapis.com"
  disable_on_destroy         = false
}

resource "google_logging_metric" "audit_configuration_changes" {
  project = module.log-export-project.project_id
  name        = "audit-configuration-changes"
  description = "Log metric for audit configuration changes"
  filter      = <<-EOF
logName:"projects/${module.log-export-project.project_id}/logs/cloudaudit.googleapis.com%2Factivity" OR logName:"projects/${module.log-export-project.project_id}/logs/cloudaudit.googleapis.com%2Fsystem_event" OR logName:"projects/${module.log-export-project.project_id}/logs/cloudaudit.googleapis.com%2Fpolicy" OR logName:"projects/${module.log-export-project.project_id}/logs/cloudaudit.googleapis.com%2Faccess_transparency" AND protoPayload.methodName="SetIamPolicy"
EOF
  metric_descriptor {
    name  = "logging.googleapis.com/user/audit-configuration-changes"
    type  = "GAUGE"
    metric_kind = "GAUGE"
    value_type = "INT64"
    unit = "1"
    display_name = "Audit Configuration Changes"
  }
}

resource "google_monitoring_alert_policy" "audit_configuration_changes_alert" {
  project                = module.log-export-project.project_id
  display_name           = "Alert for Audit Configuration Changes"
  notification_channels = [var.notification_channel]
  combiner             = "OR"

  conditions {
    display_name = "Audit Configuration Changes Condition"
    condition_threshold {
      filter          = "metric.type = \\\"logging.googleapis.com/user/audit-configuration-changes\\\" AND resource.type = \\\"gcp_project\\\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = "0"
    }
  }
}

resource "google_logging_metric" "bucket_permission_changes" {
  project = module.log-export-project.project_id
  name        = "bucket-permission-changes"
  description = "Log metric for cloud storage bucket IAM permission changes"
  filter      = <<-EOF
logName:"projects/${module.log-export-project.project_id}/logs/cloudaudit.googleapis.com%2Fdata_access" AND protoPayload.serviceName="storage.googleapis.com" AND protoPayload.methodName="storage.setIamPermissions"
EOF
  metric_descriptor {
    name  = "logging.googleapis.com/user/bucket-permission-changes"
    type  = "GAUGE"
    metric_kind = "GAUGE"
    value_type = "INT64"
    unit = "1"
    display_name = "Cloud Storage Bucket IAM Permission Changes"
  }
}

resource "google_monitoring_alert_policy" "bucket_permission_changes_alert" {
  project                = module.log-export-project.project_id
  display_name           = "Alert for Cloud Storage Bucket IAM Permission Changes"
  notification_channels = [var.notification_channel]
  combiner             = "OR"

  conditions {
    display_name = "Cloud Storage Bucket IAM Permission Changes Condition"
    condition_threshold {
      filter          = "metric.type = \\\"logging.googleapis.com/user/bucket-permission-changes\\\" AND resource.type = \\\"gcp_project\\\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = "0"
    }
  }
}

resource "google_logging_metric" "custom_role_changes" {
  project = module.log-export-project.project_id
  name        = "custom-role-changes"
  description = "Log metric for Custom IAM role creation, deletion and updating activities"
  filter      = <<-EOF
logName:"projects/${module.log-export-project.project_id}/logs/cloudaudit.googleapis.com%2Factivity" AND protoPayload.serviceName="iam.googleapis.com" AND protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole"
EOF
  metric_descriptor {
    name  = "logging.googleapis.com/user/custom-role-changes"
    type  = "GAUGE"
    metric_kind = "GAUGE"
    value_type = "INT64"
    unit = "1"
    display_name = "Custom IAM Role Changes"
  }
}

resource "google_monitoring_alert_policy" "custom_role_changes_alert" {
  project                = module.log-export-project.project_id
  display_name           = "Alert for Custom IAM Role Changes"
  notification_channels = [var.notification_channel]
  combiner             = "OR"

  conditions {
    display_name = "Custom IAM Role Changes Condition"
    condition_threshold {
      filter          = "metric.type = \\\"logging.googleapis.com/user/custom-role-changes\\\" AND resource.type = \\\"gcp_project\\\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = "0"
    }
  }
}

resource "google_logging_metric" "project_ownership_changes" {
  project = module.log-export-project.project_id
  name        = "project-ownership-changes"
  description = "Log metric for Project Ownership Assignments/Changes"
  filter      = <<-EOF
logName:"projects/${module.log-export-project.project_id}/logs/cloudaudit.googleapis.com%2Factivity" AND protoPayload.serviceName="cloudresourcemanager.googleapis.com" AND protoPayload.methodName="SetIamPolicy" AND resource.type="gcp_project"
EOF
  metric_descriptor {
    name  = "logging.googleapis.com/user/project-ownership-changes"
    type  = "GAUGE"
    metric_kind = "GAUGE"
    value_type = "INT64"
    unit = "1"
    display_name = "Project Ownership Assignments/Changes"
  }
}

resource "google_monitoring_alert_policy" "project_ownership_changes_alert" {
  project                = module.log-export-project.project_id
  display_name           = "Alert for Project Ownership Assignments/Changes"
  notification_channels = [var.notification_channel]
  combiner             = "OR"

  conditions {
    display_name = "Project Ownership Assignments/Changes Condition"
    condition_threshold {
      filter          = "metric.type = \\\"logging.googleapis.com/user/project-ownership-changes\\\" AND resource.type = \\\"gcp_project\\\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = "0"
    }
  }
}

