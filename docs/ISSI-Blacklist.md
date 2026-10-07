# ISSI Blacklist

Bar an ISSI from communicating through this brew-server. Manage it under
**Settings -> ISSI Blacklist** (admin only) or in `brew-server.toml`:

```toml
[blacklist]
issis = [4013, 4014]
```

Changes made in the Settings page apply **immediately and without a restart**
(a restart would drop every call). The config file is updated at the same time.
Editing the file by hand, or saving the raw config, restarts the server as any
other config change does.

## What a blacklisted ISSI cannot do

| Traffic | Result |
|---|---|
| Group call transmission (PTT) from it | dropped (not an emergency call) |
| Private call from it | rejected (called party not reachable) |
| Private call to it | rejected |
| SDS from it, or to it (text, status, ...) | dropped |
| SIP call to it | refused (403) |
| Stored SMS Center messages for it | stay queued until it is unblocked |

## What still works

- **Emergency calls.** A group or private call that is an emergency -- at
  priority 15, or from an ISSI that has an emergency alarm active on a
  Basestation (FlowStation forwards its radios' calls to Brew at priority 0, so
  the telemetry alarm is what marks them) -- is never held back, from or to a
  blacklisted ISSI. It shows in the red **EMERGENCY ACTIVE** ribbon at the top of
  the dashboard with the ISSI, the called group and a "blacklisted" tag, for as
  long as the call lasts. Basestation emergency alarms from telemetry appear
  in the same ribbon.

- **Ambience listening (SS-AL).** A private-call setup to it carrying the
  ambience-listening service, as dispatch sends, goes through. A blacklisted
  ISSI cannot use it to call out.
- **LIP position traffic**, in both directions: a position request to the radio
  and its location reports (SDS protocol 0x0A short reports and 0x83 long
  reports). Its positions keep plotting on the map.
- **Registration.** It still registers and is routed to, which is what lets
  dispatch reach it for the two cases above.

## Limits

- Group audio is delivered per Basestation, not per radio, so a blacklisted
  ISSI still *hears* the groups it is affiliated to. Only its own transmissions
  are blocked.
- An SDS involving a blacklisted ISSI is held until its payload arrives (the
  header does not say what kind of SDS it is), then passed only if it is LIP.
- Each server enforces its own list. In a federation, a blacklisted ISSI is
  blocked on the servers that list it; with a Basestation that is homed on
  another server the other server's list applies there.
- With **HA**, the list is written to this node's config file. Add it on the
  Standby too (or use the HA page's Config default / Apply), or a failover brings
  back the Standby's older list. The HA page names `blacklist.issis` as a
  difference.
