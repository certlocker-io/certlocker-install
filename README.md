# CertLocker customer installer

For Google Cloud, create or sign in to your account at [trust.certlocker.io](https://trust.certlocker.io).
Open **Install setup**, choose **GCP**, and enter your application SMTP settings.
Copy the account ID and four-hour installer token, then run this on your workstation.

```sh
./uncloudctl up
```

The wizard signs you into Google, lets you select your project, zones and server
sizes, and asks for DNS, VPN and deployment settings. Enter your account ID and
paste the token at the hidden prompt. The installer fetches the configuration,
administrator email and master key directly from your Trust account, checks SMTP,
and provisions and verifies two Ubuntu servers.

Grafana uses `https://grafana-cl-COMPANY.DNS_ZONE` automatically. The installer
also allowlists `88.81.117.228/32` and `185.88.0.182/32` for CertLocker update and
monitoring access without prompting.

Google installations generate a dedicated SSH provisioning key for each install
and reuse it on resume. Both SSH fields in Install setup are optional for GCP.
If you supply a username and PEM, both Google servers also authorize its public
key. For existing servers, supply their authorized SSH identity in Install setup.

For unattended setup, use `--account-id` or `CERTLOCKER_ACCOUNT_ID` and inject
`TRUST_TOKEN` or `CERTLOCKER_TOKEN` through your secret manager. Trust includes release image access in the installation configuration. The installer reads it automatically. See the [prerequisites](docs/PREREQUISITES.md).

## Existing servers on a private network

Choose **GENERIC** in Trust Install setup and enter both management IPv4 addresses and the SSH username and key already authorized on both servers. Connect your installer workstation to the customer network or VPN. The readiness check and the installer retrieve the addresses and SSH identity using your Trust account ID and hidden token. They verify SSH to both servers and test UDP/51820 between the two peers before a fresh installation. We recommend 8 GiB RAM per server for the full stack.

```sh
./uncloudctl bare-metal COMPANY --preflight-only
./uncloudctl bare-metal COMPANY
./uncloudctl update COMPANY --plan
./uncloudctl update COMPANY
./uncloudctl bare-metal uninstall COMPANY
```

The [illustrated prerequisites](docs/PREREQUISITES.md) cover SSH, memory, peer routing, ingress, DNS and image access. Follow the [bare-metal installation steps](docs/INSTALLATION.md#install-on-existing-machines) once both hosts pass.

## Google installation state and recovery

Company settings are generated under `uncloud/environments/COMPANY.json` and kept
out of Git. The included `releases/current.json` pins the approved `v1.1.30`
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
