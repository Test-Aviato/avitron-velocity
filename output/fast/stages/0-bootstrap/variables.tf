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
        protoPayload.serviceName="admin.googleapis.com" OR
        protoPayload.serviceName="cloudidentity.googleapis.com" OR
        protoPayload.serviceName="login.googleapis.com"
      FILTER
      type   = "logging"
    }
  }
  validation {
    condition = alltrue([
      for k, v in var.log_sinks :
      contains(["bigquery", "logging", "project", "pubsub", "storage"], v.type)
    ])
    error_message = "Type must be one of 'bigquery', 'logging', 'project', 'pubsub', 'storage'."
  }
}

variable "org_policies_config" {
  description = "Organization policies customization."
  type = object({
    iac_policy_member_domains = optional(list(string))
    import_defaults           = optional(bool, false)
    tag_name                  = optional(string, "org-policies")
    tag_values = optional(map(object({
      description = optional(string, "Managed by the Terraform organization module.")
      iam         = optional(map(list(string)), {})
      id          = optional(string)
    })), {})
  })
  default = {}
}

variable "organization" {
  description = "Organization details."
  type = object({
    id          = number
    domain      = optional(string)
    customer_id = optional(string)
  })
}

variable "outputs_location" {
  description = "Enable writing provider, tfvars and CI/CD workflow files to local filesystem. Leave null to disable."
  type        = string
  default     = null
}

variable "prefix" {
  description = "Prefix used for resources that need unique names. Use 9 characters or less."
  type        = string
  validation {
    condition     = try(length(var.prefix), 0) < 10
    error_message = "Use a maximum of 9 characters for prefix."
  }
}



================================================
File: fast/stages/2-networking-a-simple/data/cidrs.yaml
================================================
# skip boilerplate check
---
# Terraform will be unable to decode this file if it does not contain valid YAML
# You can retain `---` (start of the document) to indicate an empty document.

healthchecks:
  - 35.191.0.0/16
  - 130.211.0.0/22
  - 209.85.152.0/22
  - 209.85.204.0/22

rfc1918:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16

onprem_probes:
  - 10.255.255.254/32



================================================
File: fast/stages/2-networking-a-simple/data/dns-policy-rules.yaml
================================================
# skip boilerplate check
---
# start of document (---) avoids errors if the file only contains comments

# yaml-language-server: $schema=../schemas/dns-response-policy-rules.json

accounts:
  dns_name: "accounts.google.com."
  behavior: bypassResponsePolicy
aiplatform-notebook-cloud-all:
  dns_name: "*.aiplatform-notebook.cloud.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
aiplatform-notebook-gu-all:
  dns_name: "*.aiplatform-notebook.googleusercontent.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
appengine:
  dns_name: "appengine.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
appspot-all:
  dns_name: "*.appspot.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
backupdr-cloud:
  dns_name: "backupdr.cloud.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
backupdr-cloud-all:
  dns_name: "*.backupdr.cloud.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
backupdr-gu:
  dns_name: "backupdr.googleusercontent.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
backupdr-gu-all:
  dns_name: "*.backupdr.googleusercontent.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
cloudfunctions:
  dns_name: "*.cloudfunctions.net."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
cloudproxy:
  dns_name: "*.cloudproxy.app."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
composer-cloud-all:
  dns_name: "*.composer.cloud.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
composer-gu-all:
  dns_name: "*.composer.googleusercontent.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
datafusion-all:
  dns_name: "*.datafusion.cloud.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
datafusion-gu-all:
  dns_name: "*.datafusion.googleusercontent.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
dataproc:
  dns_name: "dataproc.cloud.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
dataproc-all:
  dns_name: "*.dataproc.cloud.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
dataproc-gu:
  dns_name: "dataproc.googleusercontent.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
dataproc-gu-all:
  dns_name: "*.dataproc.googleusercontent.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
dl:
  dns_name: "dl.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
gcr:
  dns_name: "gcr.io."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
gcr-all:
  dns_name: "*.gcr.io."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
gke-all:
  dns_name: "*.gke.goog."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
googleapis-all:
  dns_name: "*.googleapis.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
googleapis-private:
  dns_name: "private.googleapis.com."
  local_data:
    A:
      rrdatas:
        - 199.36.153.8
        - 199.36.153.9
        - 199.36.153.10
        - 199.36.153.11
    AAAA:
      rrdatas:
        - "2600:2d00:2:2000::"
googleapis-restricted:
  dns_name: "restricted.googleapis.com."
  local_data:
    A:
      rrdatas:
        - 199.36.153.4
        - 199.36.153.5
        - 199.36.153.6
        - 199.36.153.7
    AAAA:
      rrdatas:
        - "2600:2d00:2:1000::"
gstatic-all:
  dns_name: "*.gstatic.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
kernels-gu:
  dns_name: "kernels.googleusercontent.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
kernels-gu-all:
  dns_name: "*.kernels.googleusercontent.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
ltsapis-all:
  dns_name: "*.ltsapis.goog."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
notebooks:
  dns_name: "notebooks.cloud.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
notebooks-all:
  dns_name: "*.notebooks.cloud.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
notebooks-gu-all:
  dns_name: "*.notebooks.googleusercontent.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
packages-cloud:
  dns_name: "packages.cloud.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
packages-cloud-all:
  dns_name: "*.packages.cloud.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
pkgdev:
  dns_name: "pkg.dev."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
pkgdev-all:
  dns_name: "*.pkg.dev."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
pkigoog:
  dns_name: "pki.goog."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
pkigoog-all:
  dns_name: "*.pki.goog."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
run-all:
  dns_name: "*.run.app."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
source:
  dns_name: "source.developers.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }
storage:
  dns_name: "storage.cloud.google.com."
  local_data: { CNAME: { rrdatas: ["private.googleapis.com."] } }



================================================
File: fast/stages/2-networking-a-simple/data/hierarchical-ingress-rules.yaml
================================================
# skip boilerplate check
---
# start of document (---) avoids errors if the file only contains comments

# yaml-language-server: $schema=../schemas/firewall-policy-rules.schema.json

# allow-admins:
#   description: Access from the admin subnet to all subnets
#   priority: 1000
#   match:
#     source_ranges:
#       - rfc1918

allow-healthchecks:
  description: Enable SSH, HTTP and HTTPS healthchecks
  priority: 1001
  match:
    source_ranges:
      - healthchecks
    layer4_configs:
      - protocol: tcp
        ports: ["22", "80", "443"]

allow-ssh-from-iap:
  description: Enable SSH from IAP
  priority: 1002
  enable_logging: true
  match:
    source_ranges:
      - 35.235.240.0/20
    layer4_configs:
      - protocol: tcp
        ports: ["22"]

allow-icmp:
  description: Enable ICMP
  priority: 1003
  match:
    source_ranges:
      - 0.0.0.0/0
    layer4_configs:
      - protocol: icmp

allow-nat-ranges:
  description: Enable NAT ranges for VPC serverless connector
  priority: 1004
  match:
    source_ranges:
      - 107.178.230.64/26
      - 35.199.224.0/19



================================================
File: fast/stages/2-networking-a-simple/data/dashboards/firewall_insights.json
================================================
{
  "displayName": "Firewall Insights Monitoring",
  "gridLayout": {
    "columns": "2",
    "widgets": [
      {
        "title": "Subnet Firewall Hit Counts",
        "xyChart": {
          "chartOptions": {
            "mode": "COLOR"
          },
          "dataSets": [
            {
              "minAlignmentPeriod": "60s",
              "plotType": "LINE",
              "targetAxis": "Y1",
              "timeSeriesQuery": {
                "timeSeriesFilter": {
                  "aggregation": {
                    "perSeriesAligner": "ALIGN_RATE"
                  },
                  "filter": "metric.type=\"firewallinsights.googleapis.com/subnet/firewall_hit_count\" resource.type=\"gce_subnetwork\"",
                  "secondaryAggregation": {}
                },
                "unitOverride": "1"
              }
            }
          ],
          "timeshiftDuration": "0s",
          "yAxis": {
            "label": "y1Axis",
            "scale": "LINEAR"
          }
        }
      },
      {
        "title": "VM Firewall Hit Counts",
        "xyChart": {
          "chartOptions": {
            "mode": "COLOR"
          },
          "dataSets": [
            {
              "minAlignmentPeriod": "60s",
              "plotType": "LINE",
              "targetAxis": "Y1",
              "timeSeriesQuery": {
                "timeSeriesFilter": {
                  "aggregation": {
                    "perSeriesAligner": "ALIGN_RATE"
                  },
                  "filter": "metric.type=\"firewallinsights.googleapis.com/vm/firewall_hit_count\" resource.type=\"gce_instance\"",
                  "secondaryAggregation": {}
                },
                "unitOverride": "1"
              }
            }
          ],
          "timeshiftDuration": "0s",
          "yAxis": {
            "label": "y1Axis",
            "scale": "LINEAR"
          }
        }
      }
    ]
  }
}


================================================
File: fast/stages/2-networking-a-simple/data/dashboards/vpc_and_vpc_peering_group_quotas.json
================================================
{
  "dashboardFilters": [],
  "displayName": "VPC & VPC Peering Group Quotas",
  "labels": {},
  "mosaicLayout": {
    "columns": 12,
    "tiles": [
      {
        "height": 4,
        "widget": {
          "title": "Internal network (L4) Load Balancers per VPC Peering Group",
          "xyChart": {
            "chartOptions": {
              "mode": "COLOR"
            },
            "dataSets": [
              {
                "breakdowns": [],
                "dimensions": [],
                "measures": [],
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesQueryLanguage": "fetch compute.googleapis.com/VpcNetwork\n|{ metric\n      compute.googleapis.com/quota/internal_lb_forwarding_rules_per_peering_group/usage\n    | align next_older(1d)\n    | group_by [resource.resource_container, metric.limit_name], .max()\n  ; metric\n      compute.googleapis.com/quota/internal_lb_forwarding_rules_per_peering_group/limit\n    | align next_older(1d)\n    | group_by [resource.resource_container, metric.limit_name], .min() }\n| ratio\n| value cast_units(val()*100, \"%\")",
                  "unitOverride": ""
                }
              }
            ],
            "thresholds": [],
            "timeshiftDuration": "0s",
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            }
          }
        },
        "width": 6,
        "xPos": 6
      },
      {
        "height": 4,
        "widget": {
          "title": "Internal network (L4) Load Balancers per VPC",
          "xyChart": {
            "chartOptions": {
              "mode": "COLOR"
            },
            "dataSets": [
              {
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesQueryLanguage": "fetch compute.googleapis.com/VpcNetwork\n|{ metric\n      compute.googleapis.com/quota/internal_lb_forwarding_rules_per_vpc_network/usage\n    | align next_older(1d)\n    | group_by [resource.resource_container, metric.limit_name], .max()\n  ; metric\n      compute.googleapis.com/quota/internal_lb_forwarding_rules_per_vpc_network/limit\n    | align next_older(1d)\n    | group_by [resource.resource_container, metric.limit_name], .min() }\n| ratio\n| value cast_units(val()*100, \"%\")",
                  "unitOverride": ""
                }
              }
            ],
            "thresholds": [],
            "timeshiftDuration": "0s",
            "yAxis": {
              "label": "",
              "scale": "LINEAR"
            }
          }
        },
        "width": 6
      },
      {
        "height": 4,
        "widget": {
          "title": "Internal application (L7) Load Balancers per VPC",
          "xyChart": {
            "chartOptions": {
              "mode": "COLOR"
            },
            "dataSets": [
              {
                "breakdowns": [],
                "dimensions": [],
                "measures": [],

