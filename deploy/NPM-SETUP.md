# HexStrike endpoints behind Nginx Proxy Manager (NPM)

Topology used here:

```
 GitLab runner ──HTTPS──▶  NPM VM (Nginx Proxy Manager)  ──HTTP──▶  HexStrike VPS
                          codescan.hexstrike.example.com            :9001  (/scan/code)
                          pentest.hexstrike.example.com             :9000  (/trigger)
```

NPM runs on a **separate VM** and reverse-proxies two public hostnames (with TLS)
to the two HexStrike services running on the VPS.

---

## 1. DNS

Create two A records pointing at the **NPM VM** public IP:

```
codescan.hexstrike.example.com  ->  <NPM_VM_IP>
pentest.hexstrike.example.com   ->  <NPM_VM_IP>
```

> Two subdomains is the clean approach in NPM: the backend receives `/scan/code`
> and `/trigger` unchanged (no path rewrite needed). Path-based routing on a
> single host would require stripping the prefix — avoid it.

---

## 2. VPS side — expose ports only to the NPM VM

The services listen on `0.0.0.0:9001` and `0.0.0.0:9000`. Do **not** leave them
open to the internet — only the NPM VM needs to reach them.

Option A — host firewall (ufw), allow only the NPM VM:
```bash
sudo ufw allow from <NPM_VM_IP> to any port 9000 proto tcp
sudo ufw allow from <NPM_VM_IP> to any port 9001 proto tcp
sudo ufw deny 9000/tcp
sudo ufw deny 9001/tcp
```

Option B — bind the published ports to the private interface only, in
`deploy/docker-compose.vps.yml` (set the private IP the NPM VM routes to):
```yaml
    ports:
      - "10.0.0.5:9001:9000"   # code-scan, private IP of the VPS
      # - "10.0.0.5:9000:9000" # pentest
```

> Note on the http-blocked subnet: the firewall blocks outbound **port 80** to
> the internet, not internal traffic on ports 9000/9001. NPM → VPS on those ports
> works; just make sure the VM-to-VM route/firewall allows it.

Bring the services up on the VPS:
```bash
export REGISTRY_IMAGE=registry.example.com/security/hexstrike-ai
export WEBHOOK_TOKEN=$(openssl rand -hex 24)
docker compose -f deploy/docker-compose.vps.yml pull
docker compose -f deploy/docker-compose.vps.yml up -d
```

---

## 3. NPM — create two Proxy Hosts

For **each** host (Hosts → Proxy Hosts → Add Proxy Host):

**Details tab**
| Field | code-scan host | pentest host |
|-------|----------------|--------------|
| Domain Names | `codescan.hexstrike.example.com` | `pentest.hexstrike.example.com` |
| Scheme | `http` | `http` |
| Forward Hostname / IP | `<VPS_IP>` | `<VPS_IP>` |
| Forward Port | `9001` | `9000` |
| Cache Assets | off | off |
| Block Common Exploits | on | on |
| Websockets Support | off | off |

**SSL tab** (both hosts)
- SSL Certificate → *Request a new SSL Certificate* (Let's Encrypt)
- Force SSL: **on** · HTTP/2: **on** · HSTS: optional

**Advanced tab** (both hosts) — paste this custom Nginx config. The
`client_max_body_size` **must exceed** `HEXSTRIKE_MAX_UPLOAD_MB` (default 300):

```nginx
# Allow large repo-archive uploads to /scan/code (must be >= HEXSTRIKE_MAX_UPLOAD_MB)
client_max_body_size 350m;

# Scans can take minutes; keep the connection alive while polling / uploading
proxy_read_timeout    3600s;
proxy_send_timeout    3600s;
client_body_timeout   3600s;

# Stream the upload straight to the backend instead of buffering it on the NPM VM
proxy_request_buffering off;

# Preserve original host & client IP (optional but useful in logs)
proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

> The custom `X-Webhook-Token` header is forwarded by nginx automatically — no
> extra config needed for auth.

**Access List (optional, recommended)** — Access Lists → add one that *Allow*s
your GitLab runner egress IPs and denies the rest, then attach it to both hosts.
This is defense-in-depth on top of `WEBHOOK_TOKEN`.

---

## 4. Point the CI pipeline at the public hostnames

In your application `.gitlab-ci.yml` (using `ci/hexstrike-remote.gitlab-ci.yml`):

```yaml
variables:
  HEXSTRIKE_CODESCAN_URL: https://codescan.hexstrike.example.com
  HEXSTRIKE_PENTEST_URL:  https://pentest.hexstrike.example.com
  HEXSTRIKE_PENTEST_TARGET: https://staging.my-app.example
  HEXSTRIKE_FAIL_ON: high
```
Set the masked CI/CD variable `HEXSTRIKE_WEBHOOK_TOKEN` = the VPS `WEBHOOK_TOKEN`.

---

## 5. Verify through NPM

```bash
TOKEN=<your WEBHOOK_TOKEN>

# health (both should return JSON)
curl -s https://codescan.hexstrike.example.com/health
curl -s https://pentest.hexstrike.example.com/health

# code-scan: upload an archive
tar czf repo.tgz --exclude=.git --exclude=node_modules .
curl -s -X POST https://codescan.hexstrike.example.com/scan/code \
  -H "X-Webhook-Token: $TOKEN" -F "file=@repo.tgz" -F "fail_on=high"
# -> {"job_id":"...","status":"accepted"} ; then:
curl -s -H "X-Webhook-Token: $TOKEN" \
  https://codescan.hexstrike.example.com/status/<job_id>

# pentest
curl -s -X POST https://pentest.hexstrike.example.com/trigger \
  -H "X-Webhook-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"target":"https://staging.example","action":"pentest","profile":"quick","fail_on":"high"}'
```

---

## 6. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `413 Request Entity Too Large` on upload | `client_max_body_size` too low in the NPM Advanced tab (raise to ≥ `HEXSTRIKE_MAX_UPLOAD_MB` + margin). |
| `502 Bad Gateway` | NPM can't reach the backend — check VPS firewall allows the NPM VM on 9000/9001, correct Forward IP/Port, containers healthy (`docker ps`). |
| `401 unauthorized` | Missing/incorrect `X-Webhook-Token`, or `WEBHOOK_TOKEN` not set on the VPS service. |
| Upload times out on a slow link | Raise `client_body_timeout` / `proxy_send_timeout`; keep `proxy_request_buffering off`. |
| `504 Gateway Timeout` while polling | Polling requests are quick; a 504 means the backend hung — check container logs `docker logs hexstrike-codescan`. |
