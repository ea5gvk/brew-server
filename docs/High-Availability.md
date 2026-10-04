# High Availability (active/standby)

Two brew-servers run as a pair: one is **Active** and serves everything, the
other is **Standby** and waits. Basestations, terminals and federation peers
connect to one **virtual IP (VIP)** that always belongs to the Active node.
When the Active node fails, the Standby takes the VIP over within a couple of
seconds and the Basestations simply reconnect to the same address.

Both nodes must share a **Layer 2 network** (same LAN/VLAN), or run on the
same host. The VIP moves with `ip addr` plus a gratuitous ARP, which does not
cross routers.

## How it works

- Each node sends the other a UDP heartbeat every `heartbeat_interval_ms`
  (default 500 ms), signed with HMAC-SHA256 using `shared_secret`. A peer
  that has sent nothing valid for `dead_after_ms` (default 2 s) is dead.
- The node with the higher **weight** is the preferred Active node (equal
  weights: the higher `node_name`). When it comes back after a failure it
  takes over again, unless the current Active node has **persist** on.
- Only the Active node runs the Brew, telemetry, control and SIP listeners,
  federation, APRS, the SMS Center and the call timers. Listeners configured
  on a wildcard address (`0.0.0.0`) bind the VIP.
- A node that stops being Active hands the VIP over and restarts itself into
  Standby. Every session it carried drops and reconnects through the VIP to
  the new Active node. Calls in progress are lost; registrations and
  affiliations come back as the Basestations re-register.
- The dashboard runs on both nodes, on each node's real IP, whatever its
  role.

### Persist and manual switches

- `persist = true` (or **Persist: On** on the dashboard): once this node is
  Active it stays Active, even when a higher-weight peer comes back.
  Dashboard overrides are kept in `state_path` (`ha-state.json`) and survive
  restarts; **Config default** goes back to the config value.
- **Make Active** / **Make Standby** hand the VIP over to the other node,
  which then keeps it (a *manual hold*) until it leaves Active or an admin
  presses any Persist button.

### Split brain

If both nodes end up Active (for example after a network partition heals),
the one with persist or a manual hold wins, then the higher weight; the other
steps down at once. Set `check_gateway` to an address that only answers when
a node's uplink works (typically the default gateway): a node that cannot
ping it goes to **Fault** and never takes the VIP.

## Configuration

Both nodes use the same `vip`, `heartbeat_port` and `shared_secret`. Each
has its own `node_name`, `weight`, `real_ip` and `peer_ip` (swapped on the
other node).

```toml
[ha]
enabled = true
node_name = "bs-a"
weight = 200
persist = false
vip = "192.0.2.100/24"
vip_interface = "eth0"
real_ip = "192.0.2.11"
peer_ip = "192.0.2.12"
heartbeat_port = 9010
heartbeat_interval_ms = 500
dead_after_ms = 2000
shared_secret = "a long random string"
check_gateway = "192.0.2.1"
state_path = "ha-state.json"
```

The second node is the same, with `node_name = "bs-b"`, a lower `weight`,
`real_ip = "192.0.2.12"` and `peer_ip = "192.0.2.11"`.

The VIP must be in the same subnet as `real_ip`, and the server refuses to
start with an invalid `[ha]` section.

### Applying config changes

With HA enabled, the server **no longer restarts by itself when the config
file changes**: restarting the Active node is a failover. Changes saved on
the dashboard, or made by hand in the file, are applied with **Apply saved
config** on the High Availability page. On the Standby node it restarts at
once; on the Active node it first hands over to the Standby, then restarts.
The saved file is checked first, and a file that does not load is refused.
Apply the change on both nodes.

## Requirements

- Linux with the `ip` command (iproute2) and `arping` (iputils).
- `CAP_NET_ADMIN` (to add and remove the VIP) and `CAP_NET_RAW` (for
  `arping` and the gateway `ping`).
- Basestation TLS: when `[tls]` is enabled, the certificate must be valid for
  the VIP (or the DNS name pointing at it), since that is what Basestations
  connect to. Both nodes use the same certificate.

### systemd

```ini
[Service]
ExecStart=/usr/local/bin/brew-server /etc/brew-server.toml
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
# A clean stop releases the VIP itself; this covers a crash or kill -9.
ExecStopPost=-/usr/sbin/ip -4 addr del 192.0.2.100/24 dev eth0
Restart=always
```

On a pair sharing one host, leave out `ExecStopPost`: there is only one VIP
on the interface and it may belong to the other instance.

### Docker

The container needs the host's network and the two capabilities:

```yaml
services:
  brew-server:
    network_mode: host
    cap_add: [NET_ADMIN, NET_RAW]
    healthcheck:
      # The Brew /healthz only answers on the Active node; the dashboard's
      # answers on both ("ok active", "ok standby", ...).
      test: ["CMD-SHELL", "curl -fsSk https://192.0.2.11:9003/healthz || curl -fsS http://192.0.2.11:9003/healthz"]
```

Remove the `ports:` list (it does not apply with host networking), and use
each node's own real IP in its healthcheck.

### Two nodes on one host

Give the host two extra addresses, one per instance, and use them as
`real_ip` / `peer_ip`. Keep the listen addresses on `0.0.0.0`: the Active
instance binds the VIP, and each dashboard binds its instance's real IP, so
the two instances never collide.

## Dashboard

The **High Availability** page (`/ha`) shows both nodes: role, weight,
persist (and whether it comes from the config or the dashboard), manual hold,
who holds the VIP, the gateway check, the time since the peer's last
heartbeat, and the log of role changes. It warns when saved changes are not
applied yet, or when the two nodes' configs differ. That comparison ignores
everything that is meant to differ per node -- the whole `[ha]` section and
file locations (TLS certificate/key and CA paths, pinned certificates, the
`[storage]` and `[sms_center]` files) -- as well as comments and formatting,
so it only fires for a real setting mismatch (routing, SIP, federation,
users, ...). Both warnings name the settings involved (for example
`sip.trunks`, `route_without_affiliations`; for unapplied changes `[ha]`
settings are listed too), but never their values, since the page is
visible to non-admin users and settings include passwords. Every page
header shows this node's role.

Admins (see `[dashboard] admins`) also get **Make Active**, **Make
Standby**, **Persist On / Off / Config default**, **Apply saved config**,
and a form for every `[ha]` setting.

## Replication

The Standby keeps a copy of the Active node's **call/SDS history**
(`[storage]`) and **SMS Center queue** (`[sms_center]`), so a failover loses
neither.

- The Standby connects to the Active node's real IP on TCP `heartbeat_port`
  (the same port number as the UDP heartbeat; allow both in a firewall).
  Both sides authenticate with `shared_secret`. The stream is not encrypted:
  keep the pair on a trusted network.
- History is streamed from where the Standby left off (kept in
  `<state_path>.repl.json`, e.g. `ha-state.repl.json`) and then followed
  live. Records that already exist on the Standby are skipped, so history
  that went back and forth between the nodes is never duplicated.
- The SMS Center queue is sent in full whenever it changes and replaces the
  Standby's.
- A node returning after a failure takes the VIP back by weight only once
  its copy is up to date (the dashboard shows *Replication: in sync* and
  *Replica up to date* on the peer). Failover itself never waits, and
  neither do Make Active / Make Standby.

Live state (registrations, affiliations, calls in progress) is not
replicated: Basestations re-register when they reconnect, and calls in
progress drop. The SMS Center page on the Standby shows the replicated
queue; change it on the Active node, since the next update from the Active
node replaces the Standby's copy.
