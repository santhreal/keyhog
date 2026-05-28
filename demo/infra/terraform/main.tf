provider "google" {
  credentials = file("~/.gcp/service-account.json")
  project = "my-project"
  region  = "us-central1"
}

resource "google_storage_bucket" "logs" {
  name = "app-logs-prod"
}

variable "datadog_api_key" {
  default = "9775a026f1ca7d1c6c5af9d94d9595a4"
  sensitive = true
}
