# OCI Security List — Greyfield Honeypot Ingress Rules

## Context

Oracle Cloud controls network access at two layers:
1. **Security Lists** — subnet-level (applied to all VNICs in the subnet)
2. **Network Security Groups (NSGs)** — instance-level (optional, preferred for fine-grained control)

Greyfield uses the **default Security List** attached to the VM's VCN subnet.
These steps open the three ports that Phase 1 configures on the host.

---

## Ports to Open

| Port | Protocol | Purpose | Source CIDR |
|------|----------|---------|-------------|
| 4822 | TCP | Admin SSH (your management access) | `<your-home-ip>/32` |
| 22   | TCP | Honeypot SSH (public, attacker-facing) | `0.0.0.0/0` |
| 23   | TCP | Honeypot Telnet (public, attacker-facing) | `0.0.0.0/0` |

> **Note on port 80:** The Flask dashboard listens on 80 but is intended for
> your eyes only. Either add it now with source CIDR `<your-home-ip>/32`, or
> leave it closed and use an SSH tunnel (`ssh -L 8080:localhost:80 -p 4822 ubuntu@<vm-ip>`)
> until you need it publicly.

---

## Step-by-Step: Opening Ports in OCI Console

### Prerequisites
- OCI account with access to the tenancy where the VM is provisioned
- VM is running; note its **public IP address**

---

### 1. Navigate to the VCN

1. Open the [OCI Console](https://cloud.oracle.com)
2. In the top-left hamburger menu → **Networking** → **Virtual Cloud Networks**
3. Select the VCN attached to your Greyfield VM (likely named `vcn-YYYYMMDD-XXXX` or similar)

---

### 2. Open the Default Security List

1. In the VCN detail page, click **Security Lists** in the left-hand **Resources** panel
2. Click **Default Security List for \<vcn-name\>**

---

### 3. Add Ingress Rule — Port 4822 (Admin SSH)

> ⚠ **Restrict this to your home IP.** Using `0.0.0.0/0` here exposes your real
> admin shell to the internet. Find your home IP at [whatismyip.com](https://www.whatismyip.com).

1. Click **Add Ingress Rules**
2. Fill in:
   - **Stateless**: ☐ (leave unchecked — stateful is correct for TCP)
   - **Source Type**: CIDR
   - **Source CIDR**: `<your-home-ip>/32`
   - **IP Protocol**: TCP
   - **Source Port Range**: (leave blank — All)
   - **Destination Port Range**: `4822`
   - **Description**: `Admin SSH - Greyfield management`
3. Click **Add Ingress Rules**

---

### 4. Add Ingress Rule — Port 22 (Honeypot SSH)

1. Click **Add Ingress Rules**
2. Fill in:
   - **Stateless**: ☐
   - **Source Type**: CIDR
   - **Source CIDR**: `0.0.0.0/0`
   - **IP Protocol**: TCP
   - **Source Port Range**: (leave blank)
   - **Destination Port Range**: `22`
   - **Description**: `Honeypot SSH - Cowrie (all sources)`
3. Click **Add Ingress Rules**

---

### 5. Add Ingress Rule — Port 23 (Honeypot Telnet)

1. Click **Add Ingress Rules**
2. Fill in:
   - **Stateless**: ☐
   - **Source Type**: CIDR
   - **Source CIDR**: `0.0.0.0/0`
   - **IP Protocol**: TCP
   - **Source Port Range**: (leave blank)
   - **Destination Port Range**: `23`
   - **Description**: `Honeypot Telnet - Cowrie (all sources)`
3. Click **Add Ingress Rules**

---

### 6. Verify the Rules Are Listed

After adding all three, the **Ingress Rules** table should show (among any pre-existing rules):

| Source | Protocol | Destination Port | Description |
|--------|----------|-----------------|-------------|
| `<your-ip>/32` | TCP | 4822 | Admin SSH |
| `0.0.0.0/0`    | TCP | 22   | Honeypot SSH |
| `0.0.0.0/0`    | TCP | 23   | Honeypot Telnet |

---

## Verification (from your local machine after running setup_host.sh)

```bash
# Confirm port 4822 is reachable — should return SSH banner
nc -zv <vm-public-ip> 4822

# Confirm port 22 is reachable (will be answered by cowrie in Phase 2;
# right now nothing is listening on 2222, so nc will connect but hang or
# be refused at the application layer — that is fine)
nc -zv <vm-public-ip> 22

# Confirm port 23 is reachable (same note as above)
nc -zv <vm-public-ip> 23
```

---

## Important OCI Behaviors to Know

| Behavior | Detail |
|----------|--------|
| **Rule propagation** | Security List changes take effect immediately (no apply/deploy step) |
| **Default allow egress** | All outbound traffic is allowed by default — no egress rules needed for Phase 1 |
| **Default deny ingress** | Any port not explicitly in the Security List is blocked at the VCN level, even if UFW allows it |
| **OCI host-level iptables** | Separate from the Security List — `setup_host.sh` Step 4 flushes these. Both layers must allow traffic. |

---

## Security Reminders

- Rotate the admin SSH port (4822) to something less predictable after initial setup if you prefer
- Never add a `0.0.0.0/0` rule for port 4822
- If your home IP is dynamic, consider setting a Security List rule for `/24` or using OCI's Bastion service instead
- OCI Security Lists are stateful for TCP by default — you do not need separate egress rules for return traffic
