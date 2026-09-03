# Host deployment and operations runbook

Run every stage from the real administrator account. Do not combine stages or
skip their gates.

## Stage 1: Prepare the host

Connect on the initial real SSH port:

```powershell
ssh -i "$env:USERPROFILE\.ssh\greyfield_oracle" ubuntu@PUBLIC_IP
```

Run:

```bash
cd /opt/greyfield
bash scripts/01-prepare-host.sh
```

The script derives the administrator IPv4 from the current SSH connection and
restricts host-side port 2223 to that address. If Stage 1 must be run from the
serial console, supply it explicitly:

```bash
ADMIN_IP=YOUR_PUBLIC_IP bash scripts/01-prepare-host.sh
```

When asked about Oracle `REJECT` rules, answer yes on a dedicated disposable
honeypot. The script makes policies permissive before flushing them, then
immediately enables UFW.

Gate:

```bash
swapon --show
sudo ufw status verbose
id cowrie
```

Do not continue if the swap file, UFW, or `cowrie` user is missing.

## Stage 2: Move real SSH to 2223

First confirm the OCI Security List contains a stateful rule for TCP 2223 from
your current public IPv4 `/32`.

Keep the current port-22 session open, then run:

```bash
bash scripts/02-move-admin-ssh.sh
```

Open a second PowerShell window and test:

```powershell
ssh -i "$env:USERPROFILE\.ssh\greyfield_oracle" -p 2223 ubuntu@PUBLIC_IP
```

Gate: the second login must succeed. If it fails, use the still-open original
session to run the rollback command printed by the script. Do not close the
original session until port 2223 works.

## Stage 3: Install Cowrie

After administrator port 2223 works:

```bash
sudo -u cowrie -H bash /opt/greyfield/scripts/03-install-cowrie.sh
```

Gate:

```bash
sudo -u cowrie -H bash -lc 'cd ~/honeypot && source cowrie-env/bin/activate && cowrie status'
sudo ss -tlnp | grep -E ':(2222|2323)\b'
```

Both listeners must exist before proceeding.

## Stage 4: Activate the public honeypot ports

Run only after both prior gates pass:

```bash
bash scripts/04-activate-honeypot.sh
```

The script installs `cowrie.service`, confirms administrator access, activates
and persists redirects `22 -> 2222` and `23 -> 2323`, removes the temporary UFW
allowance for real SSH on port 22, configures Fail2ban for port 2223, and locks
root.

## Stage 5: Verify

```bash
bash scripts/verify-host.sh
```

From Windows:

```powershell
Test-NetConnection PUBLIC_IP -Port 22
Test-NetConnection PUBLIC_IP -Port 23
Test-NetConnection PUBLIC_IP -Port 2223
```

Test Cowrie externally, not through loopback:

```powershell
ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password -p 22 root@PUBLIC_IP
```

Greyfield intentionally rejects the first distinct credential and admits the
second distinct credential from a source IP.

## Stage 6: Reboot gate

```bash
sudo reboot
```

After reboot, reconnect on port 2223 and rerun:

```bash
cd /opt/greyfield
bash scripts/verify-host.sh
```

The deployment is not complete until Cowrie, Fail2ban, listeners, swap, UFW,
and both NAT redirects survive reboot.

## Stage 7: Optional public dashboard

Only begin dashboard publication after the Stage 6 reboot gate passes. Follow
the independent gates in [the dashboard guide](DASHBOARD.md): publish the static
site, create the repository-scoped key, pin GitHub's host key, configure every
operator/test IP exclusion, perform one manual publication, inspect the
published `telemetry` branch (rebuilt as a single commit atop `master` with
strictly the two allowed public files), and only then enable the hourly timer.
If carrying forward evidence from a retired sensor instance, configure
`BASELINE_SNAPSHOT` in `/etc/greyfield-dashboard/config`.

No OCI port `80` or `443` rule is needed because the dashboard is hosted by
GitHub Pages and the VM initiates an outbound Git connection.

## Logs

```bash
sudo journalctl -u cowrie -n 100 --no-pager
sudo tail -f /home/cowrie/honeypot/var/log/cowrie/cowrie.json
```

Never run files from `/home/cowrie/honeypot/var/lib/cowrie/downloads/`.
