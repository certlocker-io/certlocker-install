# CertLocker customer installer

Install CertLocker in your Google Cloud project with the guided installer:

```sh
./uncloudctl up
```

The wizard signs you into Google, lets you select your project, zones and server
sizes, and asks for company, DNS, administrator, VPN and mail settings. It creates
the two Ubuntu servers, networking, firewall rules and SSH key, then installs and
verifies the CertLocker stack. You do not need existing VMs or a configuration
file before starting.

Application email is required. Before starting, prepare your SMTP host, full
mailbox username, TLS mode, port and SMTP/app password, or arrange for CertLocker
managed mail to be provisioned in your company Trust group. Gmail requires
2-Step Verification and an [App Password](https://myaccount.google.com/apppasswords).
Setup checks SMTP access before creating servers.
See the [prerequisites](docs/INSTALLATION.md#1-prepare-your-accounts).

Grafana uses `https://grafana-cl-COMPANY.DNS_ZONE` automatically. The installer
also allowlists `88.81.117.228/32` and `185.88.0.182/32` for CertLocker update and
monitoring access without prompting.

The provisioning SSH key is generated and saved in Trust automatically for
updates, maintenance and Terminal access. Setup and resume retrieve it when needed.

Enter the CertLocker-issued Trust token at the hidden prompt. The installer uses
it to retrieve the GHCR pull credential and pulls the images pinned in the
included release manifest. For unattended use, inject `TRUST_TOKEN` or
`CERTLOCKER_TOKEN` through your secret manager. Keep tokens out of Git and JSON.

Company settings are generated under `uncloud/environments/COMPANY.json` and kept
out of Git. The included `releases/current.json` pins the approved `v1.1.28`
release; its checksum is verified and the selected release is saved for retries.

If setup stops:

```sh
./uncloudctl check
./uncloudctl resume
```

With several installations, specify `--config uncloud/environments/COMPANY.json`.
Read the [installation manual](docs/INSTALLATION.md) for prerequisites, setup,
recovery and removal. `./prepare-controller` optionally prepares the packaged
Linux toolchain ahead of time; `up` selects it automatically when needed.

This public repository contains the customer installation flow. Internal
application release tooling, live inventories, credentials and operational
history are excluded.
