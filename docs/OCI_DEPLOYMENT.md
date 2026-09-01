# OCI deployment guide

This guide provisions the infrastructure only. Do not add cloud-init or an
initialization script; host configuration is deliberately staged after the
first verified SSH login.

## 1. Record the administrator public IP

With VPNs and Cloudflare WARP disabled, run in PowerShell:

```powershell
(Invoke-RestMethod https://api.ipify.org).Trim()
```

Append `/32` when entering it in OCI. If the address changes, update the admin
rules before expecting ports 2223 or 80 to work.

## 2. Create the VCN

In OCI:

```text
Networking -> Virtual Cloud Networks -> Start VCN Wizard
```

Choose **Create VCN with Internet Connectivity**.

| Setting | Value |
|---|---|
| VCN name | `greyfield-vcn` |
| VCN CIDR | `10.0.0.0/16` |
| Public subnet | `10.0.0.0/24` |
| Private subnet | `10.0.1.0/24` |
| DNS | Enabled |
| IPv6 | Disabled |

Wait for the VCN, subnets, gateways, route tables, and security lists to become
available.

## 3. Configure the public-subnet Security List

Use the Security List for the initial build; do not attach an NSG as a second
firewall layer.

Add stateful ingress rules:

| Source CIDR | Protocol | Source port | Destination port |
|---|---|---|---|
| `0.0.0.0/0` | TCP | All | `22` |
| `0.0.0.0/0` | TCP | All | `23` |
| `YOUR_PUBLIC_IP/32` | TCP | All | `2223` |

OCI labels the checkbox **Stateless**. Leave it unchecked. Preserve the default
outbound rule and existing ICMP rules. Do not add dashboard port 80 yet.

## 4. Create the instance

```text
Compute -> Instances -> Create instance
```

| Section | Setting | Value |
|---|---|---|
| Basic | Name | `greyfield-honeypot` |
| Placement | Capacity type | On-demand |
| Image | Image | `Canonical-Ubuntu-22.04-2026.08.25-0` |
| Shape | Shape | `VM.Standard.E2.1.Micro` |
| Security | Shielded/confidential | Disabled/default |
| Network | VCN | `greyfield-vcn` |
| Network | Subnet | Public subnet |
| Network | Public IPv4 | Yes |
| Network | Private IPv4 | Automatic |
| Network | IPv6 | No |
| Network | NSG | No |
| Storage | Boot volume | Default 50 GB |
| Storage | In-transit encryption | Enabled |
| Management | Initialization script | Empty |

Confirm the selected shape is labelled **Always Free eligible** before creating
the instance.

## 5. SSH key

Recommended local key:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.ssh" | Out-Null
ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\greyfield_oracle" -C "greyfield-oci-admin"
Get-Content "$env:USERPROFILE\.ssh\greyfield_oracle.pub"
```

Paste only the `.pub` content into OCI. Never upload or commit the private key.

## 6. First connection

When the instance is running, copy its public IPv4 and run:

```powershell
ssh -i "$env:USERPROFILE\.ssh\greyfield_oracle" ubuntu@YOUR_PUBLIC_IP
```

Before continuing, verify:

```bash
cat /etc/os-release
uname -m
free -h
```

Expected: Ubuntu 22.04, `x86_64`, and approximately 1 GB RAM.

## 7. Clone Greyfield

```bash
sudo apt update
sudo apt install -y git
sudo git clone https://github.com/dedsec-terminal/greyfield.git /opt/greyfield
sudo git -C /opt/greyfield rev-parse HEAD
```

Continue with `docs/RUNBOOK.md` on the instance.

## Public IP note

An OCI ephemeral public IP currently survives a normal stop/start but is tied
to the instance/VNIC lifetime. It cannot be converted in place. A reserved IP
is optional for the first build; create and assign a new reserved address later
if Greyfield needs a stable address across instance replacement.
