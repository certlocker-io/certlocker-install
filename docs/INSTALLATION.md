# Install CertLocker on Google Cloud

Run `./uncloudctl up` to provision and install CertLocker in your company's
Google Cloud project. The guided setup creates its configuration, two Ubuntu
servers, networking, SSH identity and complete CertLocker stack. Server addresses
and a company JSON file are not prerequisites.

## 1. Prepare your accounts

Use a billed Google Cloud project with the Compute Engine API enabled. Your
Google account needs permission to inspect the project and create VMs, disks,
static addresses, networks, subnets and firewall rules. The installer checks
billing, permissions and available machine types before creating servers.

CertLocker provides your company Trust group and deployment token privately.
The token must authorize the designated GHCR pull credential and your company's
installation records. Setup asks for it with hidden input. For unattended setup,
provide `TRUST_TOKEN` or `CERTLOCKER_TOKEN` through your secret manager. The token
is not written into the generated company configuration or release manifest.

Use a Cloudflare-managed DNS zone belonging to your company. Cloudflare Load
Balancing requires its paid entitlement. Prepare a user API token scoped to your
zone and account with zone **DNS Edit**, **Zone Read**, **Load Balancers Edit**,
and account **Load Balancing: Monitors and Pools Edit** permissions. Setup asks
for it with hidden input and stores the certificate-provider settings in Trust.
A rejected token shows the HTTP status/error code and required permissions, then
lets you enter another token without restarting the wizard. A replacement is
validated before replacing a rejected saved token in your company Trust group.
An existing valid token is reused. For unattended recovery, supply the replacement
through `CLOUDFLARE_API_TOKEN`. Network failures and rate limits keep the saved
token intact and report that the check should be retried.

Choose front-office and backoffice HTTPS names directly beneath your DNS zone,
for example `certlocker.example.com` and `backoffice.example.com`.
Grafana is assigned `https://grafana-cl-COMPANY.DNS_ZONE` automatically and is
not a wizard choice. Keep the front-office and backoffice names distinct from it.
Have your initial administrator email, account domain, display name and ACME
contact email ready.

Application email is a required prerequisite. You must explicitly choose one of:

- **Customer SMTP:** prepare your SMTP host, full mailbox username, TLS mode,
  port and SMTP/app password. For Gmail, enable 2-Step Verification and create
  an [App Password](https://myaccount.google.com/apppasswords); use
  `smtp.gmail.com`, your full Gmail address and STARTTLS on port 587 (or TLS on
  port 465). Use the App Password, not your Google account password.
- **CertLocker managed mail:** arrange for SMTP settings and credentials to be
  provisioned in your company Trust group before installation. The operator's
  first-login Gmail account does not provision application mail.

There is no default mail selection or skip option. If credentials are not ready,
prepare them before continuing. Setup checks TLS and SMTP authentication before
creating servers; this check sends no email. Passwords are entered with hidden
input and stored in Trust, not in the company JSON.

## 2. Get the repository and start setup

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

- A new company/environment slug and the exact company Trust group.
- Google sign-in and a project selected from your accessible active projects.
- Two distinct Google zones and a VM type for each server. The default is
  `e2-standard-2`, with at least 2 vCPUs and 8 GiB RAM per server.
- Boot disk size, defaulting to 100 GiB per server.
- Your Cloudflare DNS zone, deployment type, front-office and backoffice URLs, administrator details
  and ACME contact email. Choose `prod` for a production installation.
- Any additional customer VPN or whitelist IPv4 addresses, separated by commas.
  Individual addresses and `/32` CIDRs are accepted; an empty answer is allowed.
- A required choice of customer SMTP or provisioned CertLocker managed mail,
  with SMTP settings and credentials for customer mail.
- The Trust deployment token if it was not supplied through the environment.

`88.81.117.228/32` and `185.88.0.182/32` are included automatically as
**certlocker updater** addresses for CertLocker monitoring and update access.
Both are added to the Google and host SSH firewall allowlists and the monitoring
allowlist, and exempted from Fail2ban.
The wizard asks only for additional customer monitoring addresses.

The wizard writes `uncloud/environments/COMPANY.json` with mode 0600. It contains
installation settings and key paths, not tokens, passwords or private key
contents. Do not publish company profiles. The provisioning SSH key is generated
automatically; no manual preparation is needed. Before creating servers, setup
saves it in your company's deployment records at **trust.certlocker.io**. It
then imports the same key into your **freshly installed company Trust**.
The operator copy supports future CertLocker updates
and maintenance; the installed copy supports browser Terminal and host access.
Retain both Trust copies while the installation is in use. Local private-key
files use memory-backed temporary storage and are removed automatically on
completion, failure or interruption. Resume retrieves the original saved key
from Trust and verifies its fingerprint; it never generates a replacement for
existing servers. No persistent local provisioning key is required.

## 4. Provisioning and installation

Before provisioning, setup checks Trust authorization, Google access, Cloudflare
routing and DNS ownership, the production ACME profile, application SMTP and the
immutable release pin. SMTP authentication sends no email. Cloudflare and SMTP
credentials are collected with hidden input and stored in Trust.

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

The repository includes the approved `v1.1.28` manifest at
`releases/current.json` and its matching checksum. A verified snapshot is saved
for the installation before servers are provisioned. Resume preserves that pin;
it does not silently advance to another release. A separately supplied manifest
can be selected with the non-secret `release_manifest` path in a saved company
profile before starting a new installation.

The supplied administrator details create the company superuser. Enter its
password at the hidden prompt. That seeded account bypasses email verification
and starts without a second factor; complete your organization's account-security
setup after first login. The dedicated provisioning SSH key is retained both at
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
the checkout, generated profile, controller state and Trust token. Resume
retrieves the original provisioning key from Trust automatically.

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
`up --config` to install a fresh pair. Supply SMTP credentials and the initial
administrator password again when running unattended after revoking Trust records.
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
