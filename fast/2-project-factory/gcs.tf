resource "google_storage_bucket" "dev_ta_0_bucket" {
  name     = var.bucket_name
  project  = var.project_id
  location = "australia-southeast1"
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_iam_member" "public_access" {
  bucket = google_storage_bucket.dev_ta_0_bucket.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}