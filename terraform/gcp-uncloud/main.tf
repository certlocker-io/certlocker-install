locals {
  name = var.resource_prefix
  machines = {
    for index, node in sort(keys(var.machine_names)) : node => {
      region  = join("-", slice(split("-", var.zones[node]), 0, length(split("-", var.zones[node])) - 1))
      zone    = var.zones[node]
      cidr    = "10.44.${(index + 1) * 10}.0/24"
      address = "10.44.${(index + 1) * 10}.10"
    }
  }
  labels = {
    environment = var.company
    managed-by  = "terraform"
    purpose     = "uncloud-ha"
    deployment  = var.deployment
  }
}

# Separate state, VPC and resources from gcp-development. No peering or prod routes.
# Compute API must already be enabled; this environment does not own project APIs.
resource "google_compute_network" "lab" {
  name                    = local.name
  auto_create_subnetworks = false
  mtu                     = 1460
}

resource "google_compute_subnetwork" "lab" {
  for_each      = local.machines
  name          = "${local.name}-${var.resource_suffixes[each.key]}"
  network       = google_compute_network.lab.id
  region        = each.value.region
  ip_cidr_range = each.value.cidr
}

resource "google_compute_firewall" "operator" {
  name          = "${local.name}-operator"
  network       = google_compute_network.lab.id
  direction     = "INGRESS"
  source_ranges = var.operator_cidrs
  target_tags   = [local.name]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# Only the two private node addresses can reach WireGuard. Uncloud traffic is
# carried inside this tunnel; no public DB, Docker API, or daemon port is opened.
resource "google_compute_firewall" "mesh" {
  name          = "${local.name}-mesh"
  network       = google_compute_network.lab.id
  direction     = "INGRESS"
  source_ranges = [for machine in values(local.machines) : "${machine.address}/32"]
  target_tags   = [local.name]
  allow {
    protocol = "udp"
    ports    = ["51820"]
  }
}

resource "google_compute_firewall" "origins" {
  name          = "${local.name}-origins"
  network       = google_compute_network.lab.id
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  target_tags   = [local.name]
  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
}


resource "google_compute_address" "node" {
  for_each = local.machines
  name     = "${local.name}-${var.resource_suffixes[each.key]}"
  region   = each.value.region
  labels   = local.labels
}

resource "google_compute_instance" "node" {
  for_each                  = local.machines
  name                      = var.machine_names[each.key]
  zone                      = each.value.zone
  machine_type              = lookup(var.machine_types, each.key, var.machine_type)
  desired_status            = lookup(var.machine_status, each.key, "RUNNING")
  allow_stopping_for_update = true
  deletion_protection       = false
  tags                      = [local.name]
  labels                    = local.labels

  boot_disk {
    auto_delete = true
    initialize_params {
      image = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64"
      size  = var.boot_disk_size_gb
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.lab[each.key].id
    network_ip = each.value.address
    access_config {
      nat_ip = google_compute_address.node[each.key].address
    }
  }

  metadata = {
    block-project-ssh-keys = "true"
    enable-oslogin         = "false"
    ssh-keys               = "${var.ssh_user}:${trimspace(var.ssh_public_key)}"
  }

  # No attached service account or API scopes. Packages are managed by Ansible.
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    provisioning_model  = "STANDARD"
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }
}
