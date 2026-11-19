# Install CertLocker

Deploy CertLocker on two Ubuntu servers. Choose **GENERIC** in Trust if you already have both servers, including cloud instances reachable over the internet. Choose **GCP** if you want the installer to create two Google Cloud VMs in your project.

## Start in Trust

1. Sign in as a super user. Select your display name in the header, then **User Details → Install setup**. [Open Trust](https://trust.certlocker.io)
2. Name the installation and select **GENERIC** or **GCP**. Enter the DNS zone, service URLs, administrator details and SMTP settings. For GENERIC, enter both servers’ SSH IPv4 addresses and an identity authorized on both. For GCP, leave the SSH fields blank to generate a provisioning key.
3. Copy the **account ID** and **deployment token** from the final screen. The installer prompts for both and retrieves the configuration and release-image credentials from Trust. New Install setup tokens default to four hours. [Prerequisites and wizard screenshots](docs/PREREQUISITES.md)

On the workstation that will run the install, clone the repository:

```sh
git clone https://github.com/certlocker-io/certlocker-install.git
cd certlocker-install
```

## Install on two existing servers

Use two dedicated Ubuntu 24.04 amd64 hosts with public or private IPv4 addresses. We recommend 8 GiB RAM per host. Before running the installer, allow these connections in your cloud security groups and any upstream firewall:

| Source | Destination | Allow |
| --- | --- | --- |
| Installer workstation | Both servers | TCP **22** for SSH and TCP **80** and **443** for web checks |
| Application clients or your load balancer | Both servers | TCP **80** (HTTP) and **443** (HTTPS) |
| Each server | The other server | UDP **51820** in both directions for the private mesh |

Enter the client or load-balancer source ranges in **Ingress IPv4 networks** in Trust so the host firewall allows the same traffic. Point your application DNS names at your ingress. For public access from arbitrary clients, a public load balancer can forward to the two hosts from its scoped source addresses. [Network checklist](docs/PREREQUISITES.md#bare-metal-network-checklist)

```sh
./uncloudctl bare-metal
```

For a readiness check before installing, run `./uncloudctl bare-metal COMPANY --preflight-only`. Replace `COMPANY` with your installation name. [Existing-server installation guide](docs/INSTALLATION.md#install-on-existing-machines)

## Create two Google Cloud VMs

Use a billed Google Cloud project with Compute Engine enabled and one free VPC network slot. Run the wizard, sign in to Google, select the project, and choose the two VM zones and sizes. The installer creates the infrastructure, deploys the application and verifies both servers. [Google Cloud prerequisites](docs/PREREQUISITES.md)

```sh
./uncloudctl up
```

## After installation

Keep the installer checkout and its controller state for maintenance. Use the front-office, backoffice and Grafana URLs from your site configuration. Grafana access is restricted to the allowed monitoring sources.

| Task | Command |
| --- | --- |
| Check an interrupted Google installation | `./uncloudctl check --config uncloud/environments/COMPANY.json`, then follow the reported recovery command |
| Continue an interrupted existing-server installation | `./uncloudctl bare-metal COMPANY --continue` |
| Preview an application update on either platform | Pull the latest installer, then run `./uncloudctl update COMPANY --plan` |
| Apply the application update | `./uncloudctl update COMPANY` |

The [release manifest](releases/current.json) identifies the application build shipped with this checkout. The installer verifies its checksum and preserves the selected build for retries. For removal, follow the procedure for your platform. [Update and removal instructions](docs/INSTALLATION.md)
