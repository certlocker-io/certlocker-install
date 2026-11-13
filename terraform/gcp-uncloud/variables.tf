variable "project_id" {
  description = "Explicit Google project for this Uncloud environment; never inferred from gcloud defaults."
  type        = string
}

variable "deployment" {
  description = "Customer deployment type: dev or prod."
  type        = string
  validation {
    condition     = contains(["dev", "prod"], var.deployment)
    error_message = "deployment must be dev or prod."
  }
}

variable "ssh_user" {
  description = "Dedicated SSH user provisioned on each VM."
  type        = string
  default     = "ucdeploy"
  validation {
    condition     = can(regex("^[a-z_][a-z0-9_-]*$", var.ssh_user))
    error_message = "ssh_user must be a valid Linux username."
  }
}

variable "operator_cidrs" {
  description = "Operator public IPv4 /32 addresses permitted to use SSH. No public application or database ports."
  type        = set(string)
  validation {
    condition     = length(var.operator_cidrs) > 0 && alltrue([for cidr in var.operator_cidrs : can(cidrnetmask(cidr)) && endswith(cidr, "/32")])
    error_message = "Supply at least one valid operator IPv4 /32; broad public ingress is not allowed."
  }
}

variable "ssh_public_key" {
  description = "Public Ed25519 key for the dedicated SSH user. Never supply a private key."
  type        = string
  validation {
    condition     = can(regex("^ssh-ed25519 [A-Za-z0-9+/=]+( [^\n\r]*)?$", trimspace(var.ssh_public_key)))
    error_message = "Supply one OpenSSH Ed25519 public key."
  }
}

variable "machine_type" {
  description = "Base VM size for each two-node CertLocker HA server."
  type        = string
  default     = "e2-standard-2"
  validation {
    condition     = contains(["e2-standard-2", "e2-standard-4", "e2-standard-8"], var.machine_type)
    error_message = "Use e2-standard-2, e2-standard-4 or e2-standard-8."
  }
}

variable "machine_status" {
  description = "Terraform owns power state. Stop either node for failure tests, both when idle."
  type        = map(string)
  default     = {}
  validation {
    condition = (
      (length(var.machine_status) == 0 || toset(keys(var.machine_status)) == toset(keys(var.machine_names))) &&
      alltrue([for status in values(var.machine_status) : contains(["RUNNING", "TERMINATED"], status)])
    )
    error_message = "Set both configured company nodes to RUNNING or TERMINATED."
  }
}

variable "boot_disk_size_gb" {
  description = "Persistent boot disk size in GiB for each VM."
  type        = number
  default     = 100
  validation {
    condition     = var.boot_disk_size_gb >= 50 && var.boot_disk_size_gb <= 1000
    error_message = "Use a boot disk size from 50 through 1000 GiB."
  }
}

variable "company" {
  type    = string
  default = "example"
}
variable "resource_prefix" {
  type    = string
  default = "certlocker-uncloud"
}
variable "machine_names" {
  type    = map(string)
  default = { certlocker-a = "certlocker-a", certlocker-b = "certlocker-b" }
  validation {
    condition     = length(var.machine_names) == 2 && toset(keys(var.machine_names)) == toset(keys(var.zones))
    error_message = "Provide two company node names with matching zone keys."
  }
}
variable "zones" {
  type    = map(string)
  default = { certlocker-a = "europe-west1-b", certlocker-b = "europe-west4-a" }
}
variable "machine_types" {
  type    = map(string)
  default = {}
}

variable "resource_suffixes" {
  type    = map(string)
  default = { certlocker-a = "a", certlocker-b = "b" }
}
