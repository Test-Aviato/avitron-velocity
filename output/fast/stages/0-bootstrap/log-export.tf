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
  source = "../../../modules/project"
  name   = var.resource_names["project-logs"]
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
  iam = {
    "roles/owner"  = [module.automation-tf-bootstrap-sa.iam_email]
    "roles/viewer" = [module.automation-tf-bootstrap-r-sa.iam_email]
  }
  services = [
    # "cloudresourcemanager.googleapis.com",
    # "iam.googleapis.com",
    # "serviceusage.googleapis.com",
    "bigquery.googleapis.com",
    "storage.googleapis.com",
    "stackdriver.googleapis.com",
    "containeranalysis.googleapis.com", #Enable Container Analysis API
  ]
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

# Define the log metric filters
resource "google_logging_metric" "audit_configuration_changes" {
  project       = module.log-export-project.project_id
  name          = "audit-configuration-changes"
  description = "Log metric filter for Audit Configuration Changes."
  filter        = <<-FILTER
  log_id("cloudaudit.googleapis.com/activity") OR
  log_id("cloudaudit.googleapis.com/system_event") OR
  log_id("cloudaudit.googleapis.com/policy") OR
  log_id("cloudaudit.googleapis.com/access_transparency")
  FILTER
  metric_descriptor {
    metric_kind = "COUNTER"
    value_type  = "INT64"
  }
}

resource "google_logging_metric" "bucket_permission_changes" {
  project       = module.log-export-project.project_id
  name          = "bucket-permission-changes"
  description = "Log metric filter for Cloud Storage Bucket IAM Permission Changes."
  filter        = <<-FILTER
  log_id("cloudaudit.googleapis.com/data_access") AND
  protoPayload.methodName="storage.setIamPermissions"
  FILTER
  metric_descriptor {
    metric_kind = "COUNTER"
    value_type  = "INT64"
  }
}

resource "google_logging_metric" "custom_role_changes" {
  project       = module.log-export-project.project_id
  name          = "custom-role-changes"
  description = "Log metric filter for Custom Role Changes."
  filter        = <<-FILTER
  log_id("cloudaudit.googleapis.com/activity") AND
  resource.type="iam.googleapis.com/Role" AND
  protoPayload.methodName="google.iam.admin.v1.CreateRole" OR
  protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR
  protoPayload.methodName="google.iam.admin.v1.UpdateRole"
  FILTER
  metric_descriptor {
    metric_kind = "COUNTER"
    value_type  = "INT64"
  }
}

resource "google_logging_metric" "project_ownership_changes" {
  project       = module.log-export-project.project_id
  name          = "project-ownership-changes"
  description = "Log metric filter for Project Ownership Assignments/Changes."
  filter        = <<-FILTER
  log_id("cloudaudit.googleapis.com/activity") AND
  resource.type="project" AND
  protoPayload.methodName="SetIamPolicy" AND
  protoPayload.authorizationInfo.permission="resourcemanager.projects.setIamPolicy"
  FILTER
  metric_descriptor {
    metric_kind = "COUNTER"
    value_type  = "INT64"
  }
}

resource "google_logging_metric" "vpc_firewall_rule_changes" {
  project       = module.log-export-project.project_id
  name          = "vpc-firewall-rule-changes"
  description = "Log metric filter for VPC Network Firewall Rule Changes."
  filter        = <<-FILTER
  log_id("cloudaudit.googleapis.com/activity") AND
  resource.type="gce_firewall_rule" AND
  (protoPayload.methodName="compute.firewalls.insert" OR
  protoPayload.methodName="compute.firewalls.delete" OR
  protoPayload.methodName="compute.firewalls.patch" OR
  protoPayload.methodName="compute.firewalls.update")
  FILTER
  metric_descriptor {
    metric_kind = "COUNTER"
    value_type  = "INT64"
  }
}

# Create alerting policies for the metric filters
resource "google_monitoring_alert_policy" "alert_audit_configuration_changes" {
  project       = module.log-export-project.project_id
  display_name = "Alert on Audit Configuration Changes"
  combiner      = "OR"
  enabled       = true
  notification_channels = [var.alert_config.audit_configuration_changes.notification_channels]
  conditions {
    display_name = "Audit Configuration Changes Condition"
    condition_threshold {
      filter     = "resource.type = \\"gcp_project\\" AND metric.type = \\"logging.googleapis.com/user/audit-configuration-changes\\""
      comparison = "COMPARISON_GT"
      threshold_value= 0
      duration    = "300s"
    }
  }
}

resource "google_monitoring_alert_policy" "alert_bucket_permission_changes" {
  project       = module.log-export-project.project_id
  display_name = "Alert on Cloud Storage Bucket IAM Permission Changes"
  combiner      = "OR"
  enabled       = true
  notification_channels = [var.alert_config.bucket_permission_changes.notification_channels]
  conditions {
    display_name = "Bucket Permission Changes Condition"
    condition_threshold {
      filter     = "resource.type = \\"gcp_project\\" AND metric.type = \\"logging.googleapis.com/user/bucket-permission-changes\\""
      comparison = "COMPARISON_GT"
      threshold_value= 0
      duration    = "300s"
    }
  }
}

resource "google_monitoring_alert_policy" "alert_custom_role_changes" {
  project       = module.log-export-project.project_id
  display_name = "Alert on Custom Role Changes"
  combiner      = "OR"
  enabled       = true
  notification_channels = [var.alert_config.custom_role_changes.notification_channels]
  conditions {
    display_name = "Custom Role Changes Condition"
    condition_threshold {
      filter     = "resource.type = \\"gcp_project\\" AND metric.type = \\"logging.googleapis.com/user/custom-role-changes\\""
      comparison = "COMPARISON_GT"
      threshold_value= 0
      duration    = "300s"
    }
  }
}

resource "google_monitoring_alert_policy" "alert_project_ownership_changes" {
  project       = module.log-export-project.project_id
  display_name = "Alert on Project Ownership Assignments/Changes"
  combiner      = "OR"
  enabled       = true
  notification_channels = [var.alert_config.project_ownership_changes.notification_channels]
  conditions {
    display_name = "Project Ownership Changes Condition"
    condition_threshold {
      filter     = "resource.type = \\"gcp_project\\" AND metric.type = \\"logging.googleapis.com/user/project-ownership-changes\\""
      comparison = "COMPARISON_GT"
      threshold_value= 0
      duration    = "300s"
    }
  }
}

resource "google_monitoring_alert_policy" "alert_vpc_firewall_rule_changes" {
  project       = module.log-export-project.project_id
  display_name = "Alert on VPC Network Firewall Rule Changes"
  combiner      = "OR"
  enabled       = true
  notification_channels = [var.alert_config.vpc_firewall_rule_changes.notification_channels]
  conditions {
    display_name = "VPC Network Firewall Rule Changes Condition"
    condition_threshold {
      filter     = "resource.type = \\"gcp_project\\" AND metric.type = \\"logging.googleapis.com/user/vpc-firewall-rule-changes\\""
      comparison = "COMPARISON_GT"
      threshold_value= 0
      duration    = "300s"
    }
  }
}
