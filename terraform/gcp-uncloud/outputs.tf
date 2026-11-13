output "nodes" {
  value = {
    for name, node in google_compute_instance.node : name => {
      region      = local.machines[name].region
      zone        = node.zone
      public_ip   = google_compute_address.node[name].address
      private_ip  = node.network_interface[0].network_ip
      status      = node.desired_status
      instance_id = node.instance_id
    }
  }
}

output "ansible_inventory" {
  description = "Non-secret inventory. Supply the operator SSH identity using --private-key."
  value = yamlencode({
    all = {
      children = {
        uncloud = {
          vars = {
            ansible_user               = var.ssh_user
            ansible_python_interpreter = "/usr/bin/python3"
            uncloud_deployment         = var.deployment
          }
          hosts = {
            for name, node in google_compute_instance.node : name => {
              ansible_host       = google_compute_address.node[name].address
              uncloud_private_ip = node.network_interface[0].network_ip
            }
          }
        }
      }
    }
  })
}
