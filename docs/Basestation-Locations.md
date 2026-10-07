# Basestation Locations

The `/map` page plots every Basestation as a radio-mast marker (blue when
connected, grey when offline) next to the mobile terminals (orange handheld
radio). A Basestation's position comes from, in order of precedence:

1. **The Basestation itself**, over telemetry (recommended).
2. **Another brew-server**, relayed over federation.
3. **`[bts_locations]`** in `brew-server.toml`, a static fallback for any
   Basestation that reports no position.

A Basestation covered by 1 or 2 never also shows its static entry.

## Reporting the position from Bost FlowStation

Add the position to the `[telemetry]` section of the FlowStation config:

```toml
[telemetry]
host = "brew.example.com"
port = 443
# ...
site_name = "Athens Hill"   # optional, shown on the map
latitude  = 37.9917         # decimal degrees, -90..90
longitude = 23.7640         # decimal degrees, -180..180
```

- Set both `latitude` and `longitude`, or neither. Values out of range are
  rejected when the config loads.
- **Nothing is sent when the position is unset or `0.0` / `0.0`.** The empty
  position is never transmitted or plotted.
- The position is sent when it changes and **re-sent every 60 seconds**, in
  case the server missed it. After a telemetry reconnect the marker can take up
  to a minute to appear.
- The same telemetry link also carries MCC / MNC, shown in the cell header
  (`MCC 202 / MNC 1 / CC 1 / LA 2`) on the dashboard. Older FlowStation builds
  do not send them and the header shows only CC / LA.

The map matches a Basestation to its static entry by the telemetry login name,
so for the fallback to be replaced cleanly it must equal the Brew username.

## Relay between brew-servers

With `[federation] loop_safe = true`, a brew-server passes the positions of its
own Basestations, and those it learned, on to its federation peers:

- Positions travel as `FED_BTS` messages. A link first sends `FED_BTS_HELLO`;
  positions go **only to peers that announced support**. Older peers and
  legacy (non loop-safe) links receive nothing.
- Every advert carries the servers it crossed, and a server never accepts one
  that went through it, so rings and meshes cannot loop. Each server forwards a
  given advert at most once.
- The origin refreshes a live position at least every 30 seconds of telemetry
  traffic and withdraws it when the Basestation's telemetry disconnects.
- A learned position not refreshed for 2 minutes is dropped, which is how a
  lost link or a dead origin server is noticed.
- A newly connected peer is sent everything currently known.
- Not replicated to an HA Standby: it rebuilds from reconnecting Basestations
  and peer refreshes after a failover.

## Static fallback

```toml
[bts_locations."1000001"]   # the Brew username the Basestation logs in as
name = "Athens HQ"
lat = 37.9917
lon = 23.7640
```

Also editable under Settings. A `0` / `0` entry is treated as not configured
and is not plotted.
