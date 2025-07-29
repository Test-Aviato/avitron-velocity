resource "google_project_service" "containeranalysis" {
  project = module.automation-project.project_id
  service = "containeranalysis.googleapis.com"

  disable_on_destroy = false
}
