# Install CertLocker

Choose the installation path that matches who owns the machines.

| Environment | Command | Resources |
| --- | --- | --- |
| Google Cloud | `./uncloudctl up` | Provisions and installs two VMs in your project. |
| Bare metal or existing private VMs | `./uncloudctl bare-metal` | Enrolls two existing servers over SSH and uses your internal routing. |

## 1. Prepare your accounts

Complete the [prerequisites and illustrated Trust setup](PREREQUISITES.md) for your environment. The installer fetches the administrator email, SMTP configuration and generated master key from the selected Trust group. The hosted Trust installation config also supplies read-only access to the release images.

## Install on existing machines

A DNS-safe Install Setup name becomes the default company slug when you run `./uncloudctl bare-metal`. Pass a company argument to set it explicitly. Clone the installer and connect your workstation to the customer network or VPN. The optional readiness check prompts for your hosted Trust account ID and installation token. It retrieves both management IPv4 addresses and the SSH username and key from GENERIC Install setup. The private key stays in temporary memory-backed storage during the check.

```sh
./uncloudctl bare-metal north-site --preflight-only
```

If you created Install setup in a locally running Trust instance, point the installer at that Gateway:

```sh
./uncloudctl bare-metal install --trust-url=http://localhost:8080/gateway/rest/api
```

Use the same URL on retries and verification runs. The default is the hosted Trust Gateway. Remote gateways require HTTPS. A packaged controller using localhost requires Docker host networking (enable host networking in Docker Desktop).

In Trust, choose **GENERIC** and enter the short SSH hostnames in the same order as the two management IPs (for example, `dev02`, then `dev03`). The installer checks each hostname over SSH before changing either server. Enter the Cloudflare zone and the three HTTPS URLs for the front office, backoffice and Grafana. Use distinct names one label below the zone, such as `https://install.example.org`, `https://backoffice-install.example.org` and `https://grafana-cl-install.example.org`. Your internal DNS must resolve them to the private ingress.

Enter the zone's Cloudflare API token in Trust Install Setup or at the installer's hidden prompt. Trust stores it in the install group and puts its secret ID in the install configuration. The installer validates the credential against Cloudflare. Use the deployment token shown by Install Setup (the configuration's `access_token`) at the installer login prompt.

The following excerpt shows the network fields in the generated `<install-name>_install_config` Trust secret. Each hostname corresponds to the IP at the same position. Trust fills in the Cloudflare secret ID.

```json
{
  "server_ips": ["192.0.2.11", "192.0.2.12"],
  "server_hostnames": ["node-a", "node-b"],
  "dns_zone": "example.org",
  "front_url": "https://install.example.org",
  "backoffice_url": "https://backoffice-install.example.org",
  "grafana_url": "https://grafana-cl-install.example.org",
  "cloudflare_secret_id": "example-secret-id"
}
```

For older Trust records without saved addresses, pass both management addresses after `north-site` or enter them when prompted. If Trust has saved addresses, any positional addresses must match that pair in order.

The installer selects peer addresses from the hosts' IPv4 routes and verifies UDP connectivity on port 51820 on fresh servers. To override discovery, supply `--peer-1` and `--peer-2` or configure the nodes' `wireguard_endpoint` values. On enrolled servers, use `--verify-only` to check the installed mesh.

Confirm the printed hostnames, VPN sources, RAM and peer addresses. We recommend 8 GiB RAM per host for the full stack. You can bring smaller instances, including 4 GiB hosts. To pin expected hostnames, supply a JSON `--config` with `nodes.north-site-a.expected_hostname` and `nodes.north-site-b.expected_hostname`.

Once both servers pass, run the install using the SSH identity you enrolled in Trust. This example allows Grafana access from one VPN egress address and web traffic from a private load balancer.

```sh
./uncloudctl bare-metal north-site \
  --deployment dev --dns-zone example.com --acme-email admin@example.com \
  --vpn-ip 192.0.2.30 --ingress-cidr 192.0.2.40/32
```

Enter the account ID and token at the prompts. The installer checks both hosts again before hardening, then uses the pinned release, private mesh, database, application and certificate playbooks. Configure the application and Grafana names in your internal DNS. This path leaves public application DNS and load-balancer provisioning to your network team.

Retry using the same company, addresses, configuration and installation state. Add `--continue` to resume completed stages, or `--verify-only` to verify an installed pair. The `up`, `resume` and `destroy` commands below manage Google infrastructure.

### First login and Trust chat

After creating the superuser, the installer displays its email and password in an interactive terminal. A resumed installation that preserves the existing password cannot display it. Keep the terminal private. Automation can inject `CERTLOCKER_INITIAL_ADMIN_PASSWORD` through its secret manager.

For a verified install notification in the operator Trust Google Chat space, set `CERTLOCKER_INSTALL_CHAT_WEBHOOK_FILE` to an owner-only file on the controller containing that space's incoming webhook URL. Alternatively configure the operator Trust webhook secret. The message includes release, hostnames, addresses and URLs. If delivery is pending, retry it with `python3 scripts/uncloud_install_notification.py /path/to/installation-state`. A confirmed delivery writes a receipt in that directory.

Successful bare-metal and Google installs write a completion report to the Trust that issued the setup. In that Trust, open Back Office, Accounts, select the account, then open Stats to see the reported installation count and the latest report time. Local tests using `--trust-url` report to the selected local Trust. These historical reports survive uninstall.

Google uses the same Install setup site, mail and administrator settings, release manifest and rolling updater. Choose GCP in Trust and run `./uncloudctl up`. Google creates the VM pair in the selected project and zones, assigns its private addresses and configures Cloudflare load balancing. Optional server hostnames in Trust become VM names.

### Update an installed pair

From the same installer checkout and controller used for installation:

```sh
git pull --ff-only
./uncloudctl update COMPANY --plan
./uncloudctl update COMPANY
```

With one active inventory, `./uncloudctl update` selects it automatically. Before an update, open Tokens in the Trust instance that issued Install setup. Check the expiry of the group deployment token and its Install setup configuration token. Select Renew on expired tokens. At the installer prompt enter the reusable group deployment token (the `access_token` in Install setup). The token restricted to the configuration secret can only read that secret. Use the same `--trust-url` for local Trust. The command checks the bundled `releases/current.json` against its checksum, stages the pinned images, verifies the peer and drains one node at a time. HAProxy and both nodes must be healthy before rollout. After an interrupted rollout, correct the reported failure and retry with the same checkout. The controller records the new release after the final HA checks. If requests remain active when the drain times out, the rollout stops. On installations with a single API owner, handing ownership to the peer stops the old API before its replacement becomes ready. Interactive requests can fail during that interval even with a healthy external load balancer.

### Uninstall from existing servers

```sh
./uncloudctl bare-metal uninstall COMPANY
```

Supply a token for the installed group's provisioning key, or use `--ssh-key PATH` or `--workstation-ssh` for an existing authorized login. Use `--trust-url` if the provisioning key is in local Trust. The uninstaller verifies both SSH host keys, machine IDs and enrollment names, then asks you to type the company name. `--yes` confirms unattended deletion. It destroys the application, monitoring and PostgreSQL data, removes the mesh and startup units, verifies both machines, revokes the company deployment credentials in the issuing Trust and archives the local installation records. With workstation SSH or a supplied SSH key, host teardown can proceed while the group token is inactive. A current group token is required to finish Trust cleanup. If cleanup stops there, rerun the same uninstall command with an active group token before reinstalling. The uninstaller resumes after host verification. The original Install setup inputs and historical completion reports are retained.

## 2. Start Google Cloud setup

```sh
git clone https://github.com/certlocker-io/certlocker-install.git
cd certlocker-install
./uncloudctl up
```

Use macOS or Linux. The launcher prepares missing Python on supported systems
and selects a packaged Linux controller when the native toolchain is incomplete.
On macOS, complete any Homebrew, Docker Desktop, administrator and first-run
prompts. Debian/Ubuntu can install Docker through the bootstrap; other Linux
distributions need a Docker-compatible engine prepared by your administrator.
Google browser login stays on your workstation.

To prepare the toolchain before installation, optionally run:

```sh
./prepare-controller
```

The controller includes checksum-pinned Terraform, Google CLI and mesh CLI,
plus Ansible and pinned collections. Its image build contains no credentials.
At runtime it mounts this checkout and your SSH directory, uses memory-backed
temporary storage, and disables container swap.

## 3. Answer the wizard

Setup asks for:

- Your Trust account ID, hidden Install setup token and a new company/environment slug.
- Google sign-in and a project selected from your accessible active projects.
- Two distinct Google zones and a VM type for each server. The default is
  `e2-standard-2`, with at least 2 vCPUs and 8 GiB RAM per server.
- Boot disk size, defaulting to 100 GiB per server.
- Your Cloudflare DNS zone, deployment type, front-office and backoffice URLs, administrator details
  and ACME contact email. Choose `prod` for a production installation.
- Any additional customer VPN or whitelist IPv4 addresses, separated by commas.
  Individual addresses and `/32` CIDRs are accepted; an empty answer is allowed.

`88.81.117.228/32` and `185.88.0.182/32` are included automatically as
**certlocker updater** addresses for CertLocker monitoring and update access.
Both are added to the Google and host SSH firewall allowlists and the monitoring
allowlist, and exempted from Fail2ban.
The wizard asks only for additional customer monitoring addresses.

The wizard writes `uncloud/environments/COMPANY.json` with mode 0600. It contains
installation settings and key paths, not tokens, passwords or private key
contents. Keep your controller state private and backed up. Google provisioning
generates a dedicated Ed25519 key in the private company state directory.
Retries reuse it. After host enrollment the installer also saves the verified
identity in your hosted Trust group and the installed Trust for maintenance and
browser Terminal access. Verified teardown removes the controller key.

For existing Ubuntu servers, including private VMs in AWS or Azure, follow the
[bare-metal installation steps](#install-on-existing-machines).

## 4. Provisioning and installation

Before provisioning, setup checks Trust authorization, Google access, Cloudflare
routing and DNS ownership, the production ACME profile, application SMTP and the
immutable release pin. SMTP authentication sends no email. Cloudflare access is enrolled on your workstation. SMTP credentials come from your Trust install configuration.

Terraform creates the two Ubuntu 24.04 servers, their private network, persistent
boot disks, static public addresses and bounded firewall rules. SSH is restricted
to the installation administrator and CertLocker updater. HTTPS is public;
WireGuard is restricted to the peer private addresses. Database and monitoring
service ports stay private. Before setup probes either host, the installer waits
up to ten minutes per server for the dedicated SSH key and passwordless sudo to
work. Installer SSH connections disable agent identities so unrelated keys cannot
exhaust authentication attempts. Failures identify authentication, reachability,
host-key or sudo problems; host-key mismatches stop immediately.

The installer uses Terraform's verified server outputs to configure the hosts,
private mesh, database, application, certificate automation and monitoring. It
retrieves the GHCR credential through Trust, authenticates Docker using temporary
memory-backed configuration and pulls all eight application images at the pinned
digests. Downloads run as a remote job with a 30-minute limit and polling, so a
long image pull does not depend on one continuous SSH session. Temporary registry
authentication is removed even if a pull fails.

The repository includes the approved `v1.1.30` manifest at
`releases/current.json` and its matching checksum. A verified snapshot is saved
for the installation before servers are provisioned. Resume preserves that pin;
it does not silently advance to another release. A separately supplied manifest
can be selected with the non-secret `release_manifest` path in a saved company
profile before starting a new installation.

The supplied administrator details create the company superuser. Enter its
password at the hidden prompt. Setup marks the administrator email as verified. At sign-in, a new administrator
receives a verification code through the configured SMTP server. Setting a bootstrap
password for an existing administrator preserves an enrolled second factor and
enables email codes if the account has none. The dedicated provisioning SSH key is retained both at
**trust.certlocker.io** for updates and maintenance and in your **freshly
installed company Trust** for browser Terminal and host access. Certificate renewal
uses separate restricted host automation access.

Setup runs installation verification and publishes healthy Cloudflare routing.
Normal `up` does not run disruptive failover drills. Open your front office and
backoffice and verify sign-in, HTTPS and mail. Access Grafana and its
`/prometheus/` path from an allowed VPN address. Grafana DNS is unproxied so the
origin can check the real client address.

## 5. Check or resume

Each interactive `up` creates a new named installation. If setup stopped, keep
the checkout, generated profile and private controller state. Resume uses the original
Google provisioning key and requires a valid token for the saved account and group.

```sh
./uncloudctl check
./uncloudctl resume
```

When several companies are present, select the generated profile explicitly:

```sh
./uncloudctl check --config uncloud/environments/COMPANY.json
./uncloudctl resume --config uncloud/environments/COMPANY.json
```

`check` reports infrastructure, inventory, installation markers and the next
command. Resume reuses the same pair, completing interrupted provisioning with
a create-only plan when safe and continuing from the first incomplete setup
stage. It refuses a replacement SSH key or another installation's state.
Saved mesh connections are rebound to the current run's temporary key file before
connecting, so expired temporary paths from an earlier run do not prevent resume.
If failure occurred before VMs were created, `check` can direct you to retry
`up --config uncloud/environments/COMPANY.json` instead.

Run external dependency checks without provisioning VMs using:

```sh
./uncloudctl resume --config uncloud/environments/COMPANY.json --preflight-only
```

For unattended setup, use a completed company profile and secret-manager-injected
credentials:

```sh
./uncloudctl up --non-interactive --config uncloud/environments/COMPANY.json
```

This optional mode does not change the normal wizard-based workflow.

## 6. Remove an installation

To remove a selected installation, including its owned DNS and Trust records:

```sh
./uncloudctl destroy --config uncloud/environments/COMPANY.json --remove-dns --remove-trust
```

Teardown checks company ownership, withdraws routing before releasing origin IPs
and revokes company secrets after infrastructure removal. It does not revoke the
shared registry credential itself. Removal destroys the selected servers and
their boot disks; preserve required data and backups first.

After verified teardown, the active inventory is archived under that run's
`retired-inventory/` directory. The saved company profile can then be used with
`up --config` to install a fresh pair. Keep the original Install setup records and provide the initial administrator
password again when running unattended after revoking deployment records.
If a repeated `destroy --remove-dns` runs after its Cloudflare record was revoked,
inject `CLOUDFLARE_API_TOKEN`; teardown validates it before checking owned routing.

Local cleanup is separate:

```sh
./uncloudctl clean --config uncloud/environments/COMPANY.json
```

`clean` removes the generated local profile, state, inventory and dedicated SSH
key. It does not destroy Google resources. Follow `check` and complete cloud
teardown before cleaning local ownership records.

## Operation and troubleshooting

Docker logs rotate at 20 MiB across five files. Loki retains seven days;
Prometheus retains up to 30 days capped at 4 GiB. Weekly cleanup preserves
volumes and pinned images. Monitor free disk and certificate automation health.
Keep host certificate automation tokens active so renewals can continue.

For Google errors, check billing, Compute Engine API availability, account
permissions and quota. For GHCR errors, check that the Trust token can read the
registry record and that its credential can pull the pinned images. For
Cloudflare errors, check token scope, Load Balancing entitlement and DNS ownership.
Reuse the enrolled DNS settings on retry rather than resetting Trust records.

Generated inventory is under `inventory/uncloud/COMPANY/`. Native controller
state is under `~/.local/share/certlocker/cl-deployment/COMPANY/`; the packaged
controller home is under `~/.local/share/certlocker/controller-home/`. Use the
same native or packaged mode for resume. Share redacted diagnostics through your
private support channel. Coordinate live failure and restore acceptance testing
with CertLocker before production handover.

### Frontend request allowance

Customer UI, Back Office and REST requests share a limit of 400 requests per client
IP per 10 seconds at each HAProxy origin. Set `"http_rate_limit": 400` in the company
JSON to change it (integer 1–999999); setup and redeploy render this into ingress.
Cloudflare requests use the verified CDN peer's `CF-Connecting-IP`; direct clients
use their connection IP and cannot spoof that header. Readiness checks are exempt.
