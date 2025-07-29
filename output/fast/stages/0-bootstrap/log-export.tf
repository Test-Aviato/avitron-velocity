resource "google_logging_metric" "audit_configuration_changes" {
  project       = module.log-export-project.project_id
  name          = "audit-configuration-changes"
  description = "Audit configuration changes"
  filter = <<-FILTER
    logName = "projects/${module.log-export-project.project_id}/logs/cloudaudit.googleapis.com%2Factivity"
    AND protoPayload.methodName="SetIamPolicy"
    AND protoPayload.serviceName="cloudresourcemanager.googleapis.com"
  FILTER
  metric_descriptor {
    metric_kind = "COUNTER"
    type        = "logging.googleapis.com/user/audit_configuration_changes"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "alert_audit_configuration_changes" {
  project        = module.log-export-project.project_id
  display_name   = "Alert for Audit Configuration Changes"
  enabled        = true
  combiner       = "OR"
  notification_channels = var.alert_config.notification_channels
  conditions {
    display_name = "Audit Configuration Changes"
    condition_threshold {
      filter     = "metric.type = \"logging.googleapis.com/user/audit_configuration_changes\" AND resource.project_id = \"${module.log-export-project.project_id}\""
      duration   = "300s"
      comparison = "DURATION_MORE_THAN"
      threshold_value = 0
      trigger {
        count = 1
      }
    }
  }
}

resource "google_logging_metric" "bucket_permission_changes" {
  project       = module.log-export-project.project_id
  name          = "bucket-permission-changes"
  description = "Cloud Storage Bucket IAM Permission Changes"
  filter = <<-FILTER
logName = "projects/${module.log-export-project.project_id}/logs/cloudaudit.googleapis.com%2Fdata_access"
AND protoPayload.serviceName="storage.googleapis.com"
AND protoPayload.methodName="storage.setIamPermissions"
  FILTER
  metric_descriptor {
    metric_kind = "COUNTER"
    type        = "logging.googleapis.com/user/bucket_permission_changes"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "alert_bucket_permission_changes" {
  project        = module.log-export-project.project_id
  display_name   = "Alert for Cloud Storage IAM Permission Changes"
  enabled        = true
  combiner       = "OR"
  notification_channels = var.alert_config.notification_channels

  conditions {
    display_name = "Cloud Storage Bucket IAM Permission Changes"
    condition_threshold {
      filter     = "metric.type = \"logging.googleapis.com/user/bucket_permission_changes\" AND resource.project_id = \"${module.log-export-project.project_id}\""
      duration   = "300s"
      comparison = "DURATION_MORE_THAN"
      threshold_value = 0
      trigger {
        count = 1
      }
    }
  }
}

resource "google_logging_metric" "custom_role_changes" {
  project       = module.log-export-project.project_id
  name          = "custom-role-changes"
  description = "Custom Role Changes"
  filter = <<-FILTER
logName = "projects/${module.log-export-project.project_id}/logs/cloudaudit.googleapis.com%2Factivity"
AND protoPayload.serviceName="iam.googleapis.com"
AND (protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole")
  FILTER
  metric_descriptor {
    metric_kind = "COUNTER"
    type        = "logging.googleapis.com/user/custom_role_changes"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "alert_custom_role_changes" {
  project        = module.log-export-project.project_id
  display_name   = "Alert for Custom Role Changes"
  enabled        = true
  combiner       = "OR"
  notification_channels = var.alert_config.notification_channels

  conditions {
    display_name = "Custom Role Changes"
    condition_threshold {
      filter     = "metric.type = \"logging.googleapis.com/user/custom_role_changes\" AND resource.project_id = \"${module.log-export-project.project_id}\""
      duration   = "300s"
      comparison = "DURATION_MORE_THAN"
      threshold_value = 0
      trigger {
        count = 1
      }
    }
  }
}

resource "google_logging_metric" "project_ownership_changes" {
  project       = module.log-export-project.project_id
  name          = "project-ownership-changes"
  description = "Project Ownership Assignments/Changes"
  filter = <<-FILTER
logName = "projects/${module.log-export-project.project_id}/logs/cloudaudit.googleapis.com%2Factivity"
AND protoPayload.methodName="SetIamPolicy"
AND protoPayload.serviceName="cloudresourcemanager.googleapis.com"
AND resource.type="project"
AND protoPayload.request.policy.bindings.role="roles/owner"
  FILTER
  metric_descriptor {
    metric_kind = "COUNTER"
    type        = "logging.googleapis.com/user/project_ownership_changes"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "alert_project_ownership_changes" {
  project        = module.log-export-project.project_id
  display_name   = "Alert for Project Ownership Assignments/Changes"
  enabled        = true
  combiner       = "OR"
  notification_channels = var.alert_config.notification_channels

  conditions {
    display_name = "Project Ownership Assignments/Changes"
    condition_threshold {
      filter     = "metric.type = \"logging.googleapis.com/user/project_ownership_changes\" AND resource.project_id = \"${module.log-export-project.project_id}\""
      duration   = "300s"
      comparison = "DURATION_MORE_THAN"
      threshold_value = 0
      trigger {
        count = 1
      }
    }
  }
}

resource "google_logging_sink" "audit_logs" {
  name        = "all-logs-to-gcs"
  project     = module.log-export-project.project_id
  destination = "storage.googleapis.com/${module.automation-tf-output-gcs.name}"  # Replace with your GCS bucket
  filter      = "NOT logName:\"projects/${module.log-export-project.project_id}/logs/cloudaudit.googleapis.com%2Fdata_access\""
}
