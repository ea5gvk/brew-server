//! Best-effort extraction of geographic coordinates from free-text SDS bodies.
//!
//! Position beacons that arrive as *text* (APRS strings, plain decimal degrees,
//! or Maidenhead grid locators) can be turned into latitude/longitude here.
//!
//! IMPORTANT LIMITATION: binary LIP position beacons (SDS protocol id 0x0A) do
//! **not** reach this server with their payload intact — the Basestation decodes
//! SDS text best-effort and emits an empty string for binary LIP, so there are
//! no coordinate bytes to parse. Only textual beacons are recoverable here. See
//! the README "Position mapping" section for the Basestation-side fix needed to
//! plot binary LIP.

/// A decoded geographic position in decimal degrees (WGS-84).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LatLon {
    pub lat: f64,
    pub lon: f64,
}

impl LatLon {
    fn new(lat: f64, lon: f64) -> Option<Self> {
        // Exactly 0/0 (Null Island) is the "no fix" value every beacon format uses; never a position.
        if lat.is_finite() && lon.is_finite() && (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)
            && (lat != 0.0 || lon != 0.0)
        {
            Some(LatLon { lat, lon })
        } else {
            None
        }
    }
}

/// Attempts to parse a latitude/longitude pair out of an arbitrary text body.
/// Tries, in order: APRS uncompressed position, decimal degrees, then Maidenhead
/// locator. Returns `None` if nothing coordinate-like is found.
pub fn parse_position(text: &str) -> Option<LatLon> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    parse_aprs(t).or_else(|| parse_decimal(t)).or_else(|| parse_maidenhead(t))
}

/// Decodes a TETRA LIP (ETSI TS 100 392-18) **short location report** from the
/// raw SDS user-data bytes, including the leading `0x0A` protocol-id byte.
///
/// Wire layout (MSB-first, after the 0x0A PID byte):
///   PDU type            2 bits  (0b00 = short location report)
///   time elapsed        2 bits
///   longitude          25 bits  signed, degrees = raw * 360 / 2^25
///   latitude           24 bits  signed, degrees = raw * 180 / 2^24
///   position error      3 bits
///   horizontal velocity 7 bits
///   direction of travel 4 bits
///   (type-of-additional-data + additional data follow; ignored here)
///
/// Verified against a live beacon `0a 01 0e 62 39 b0 43 9a ff e0 20` which
/// decodes to 37.991956 N, 23.764189 E (Athens). Returns `None` if the buffer is
/// not a short location report or is too short.
pub fn decode_lip(bytes: &[u8]) -> Option<LatLon> {
    // Need the PID byte plus at least PDU-type+time+lon+lat = 2+2+25+24 = 53 bits
    // -> 7 bytes of PDU, so 8 bytes total including the 0x0A PID.
    if bytes.len() < 8 || bytes[0] != 0x0A {
        return None;
    }
    let pdu = &bytes[1..];
    let bit = |i: usize| -> u32 { ((pdu[i / 8] >> (7 - (i % 8))) & 1) as u32 };
    let take = |start: usize, n: usize| -> u32 {
        let mut v = 0u32;
        for k in 0..n {
            v = (v << 1) | bit(start + k);
        }
        v
    };
    let sign_extend = |v: u32, n: usize| -> i32 {
        let shift = 32 - n;
        ((v << shift) as i32) >> shift
    };

    let total_bits = pdu.len() * 8;
    if total_bits < 4 + 25 + 24 {
        return None;
    }

    let pdu_type = take(0, 2);
    if pdu_type != 0 {
        // Only the short location report is handled; other LIP PDUs (long
        // report, velocity report, request/response) are not decoded here.
        return None;
    }
    let _time_elapsed = take(2, 2);
    let lon_raw = take(4, 25);
    let lat_raw = take(29, 24);

    let lon = sign_extend(lon_raw, 25) as f64 * 360.0 / (1u64 << 25) as f64;
    let lat = sign_extend(lat_raw, 24) as f64 * 180.0 / (1u64 << 24) as f64;
    // An all-zero lat/lon is LIP's "no position fix yet" sentinel (Null Island),
    // not a real location — do not plot it.
    if lon_raw == 0 && lat_raw == 0 {
        return None;
    }
    LatLon::new(lat, lon)
}

/// Decodes a hex string (e.g. `"0a010e6239..."`, optional spaces/`0x`) into bytes
/// and runs [`decode_lip`]. Convenience for payloads carried as hex over
/// telemetry.
pub fn decode_lip_hex(hex: &str) -> Option<LatLon> {
    let cleaned: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() < 2 || cleaned.len() % 2 != 0 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
        .collect();
    decode_lip(&bytes?)
}

/// Decodes the Motorola-style LIP "long location report" seen from MTH-series
/// radios, whose SDS user-data begins with `0x83` (SDS-TL header) followed by a
/// `00 <seq> 80 13 13 23 …` LIP block. Latitude and longitude sit at fixed bit
/// offsets within the SDS data:
///   - latitude:  bit offset 119, 24 bits, degrees = raw * 180 / 2^23
///   - longitude: bit offset 152, 25 bits, degrees = raw * 360 / 2^25
///
/// Verified against five live reports from a stationary MTH850 which all decode
/// to ~37.9917 N, 23.7640 E (the radio's true location). `data` is the SDS
/// user-data (the bytes after the 20-byte Brew frame header), starting at `0x83`.
pub fn decode_lip_long(data: &[u8]) -> Option<LatLon> {
    // Need at least 152 + 25 = 177 bits -> 23 bytes of SDS data.
    if data.len() < 23 || data[0] != 0x83 {
        return None;
    }
    let bit = |i: usize| -> u32 { ((data[i / 8] >> (7 - (i % 8))) & 1) as u32 };
    let take = |start: usize, n: usize| -> u32 {
        let mut v = 0u32;
        for k in 0..n {
            v = (v << 1) | bit(start + k);
        }
        v
    };
    let lat_raw = take(119, 24);
    let lon_raw = take(152, 25);
    if lat_raw == 0 && lon_raw == 0 {
        return None; // no-fix sentinel
    }
    let lat = lat_raw as f64 * 180.0 / (1u64 << 23) as f64;
    let lon = lon_raw as f64 * 360.0 / (1u64 << 25) as f64;
    LatLon::new(lat, lon)
}

/// APRS uncompressed position: `DDMM.mmN` / `DDMM.mmS` for latitude and
/// `DDDMM.mmE` / `DDDMM.mmW` for longitude, in that order, separated by a single
/// symbol-table character or common punctuation. Examples:
///   `4426.12N/02606.55E`   `4426.12N\02606.55E-`   `4426.12N 02606.55E`
/// The leading `!`, `=`, `@`, `/` APRS data-type indicators and any timestamp
/// are tolerated because we scan for the lat/lon tokens directly.
fn parse_aprs(text: &str) -> Option<LatLon> {
    let bytes = text.as_bytes();
    // Find a latitude token: 4 digits, '.', 2 digits, then N/S.
    for i in 0..bytes.len() {
        if let Some((lat, lat_end)) = aprs_lat_at(text, i) {
            // Longitude may follow after exactly one separator char (symbol table
            // id in APRS), or directly, or after whitespace.
            for skip in 0..=1usize {
                let j = lat_end + skip;
                if let Some((lon, _)) = aprs_lon_at(text, j) {
                    return LatLon::new(lat, lon);
                }
            }
            // Also tolerate arbitrary whitespace between the two tokens.
            let mut j = lat_end;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if let Some((lon, _)) = aprs_lon_at(text, j) {
                return LatLon::new(lat, lon);
            }
        }
    }
    None
}

/// Parses an APRS latitude `DDMM.mmN` at byte offset `i`; returns the signed
/// decimal degrees and the byte offset just past the hemisphere letter.
fn aprs_lat_at(text: &str, i: usize) -> Option<(f64, usize)> {
    let b = text.as_bytes();
    // DD MM . mm H  -> 2 + 2 + 1 + 2 + 1 = 8 chars (mm may be more/fewer digits)
    if i + 4 > b.len() { return None; }
    if !(b[i].is_ascii_digit() && b[i + 1].is_ascii_digit() && b[i + 2].is_ascii_digit() && b[i + 3].is_ascii_digit()) {
        return None;
    }
    let deg: f64 = text.get(i..i + 2)?.parse().ok()?;
    // minutes: two integer digits, optional fractional part
    let mut k = i + 2;
    let min_start = k;
    k += 2; // integer minutes
    if k < b.len() && b[k] == b'.' {
        k += 1;
        while k < b.len() && b[k].is_ascii_digit() {
            k += 1;
        }
    }
    let minutes: f64 = text.get(min_start..k)?.parse().ok()?;
    if k >= b.len() { return None; }
    let hemi = b[k];
    let sign = match hemi {
        b'N' | b'n' => 1.0,
        b'S' | b's' => -1.0,
        _ => return None,
    };
    let val = sign * (deg + minutes / 60.0);
    Some((val, k + 1))
}

/// Parses an APRS longitude `DDDMM.mmE` at byte offset `i`.
fn aprs_lon_at(text: &str, i: usize) -> Option<(f64, usize)> {
    let b = text.as_bytes();
    if i + 5 > b.len() { return None; }
    if !(0..5).all(|o| b[i + o].is_ascii_digit()) {
        return None;
    }
    let deg: f64 = text.get(i..i + 3)?.parse().ok()?;
    let mut k = i + 3;
    let min_start = k;
    k += 2;
    if k < b.len() && b[k] == b'.' {
        k += 1;
        while k < b.len() && b[k].is_ascii_digit() {
            k += 1;
        }
    }
    let minutes: f64 = text.get(min_start..k)?.parse().ok()?;
    if k >= b.len() { return None; }
    let sign = match b[k] {
        b'E' | b'e' => 1.0,
        b'W' | b'w' => -1.0,
        _ => return None,
    };
    let val = sign * (deg + minutes / 60.0);
    Some((val, k + 1))
}

/// Decimal degrees: `lat, lon` or `lat lon`, optionally with a leading label.
/// Accepts an optional trailing hemisphere letter on each (`44.43N, 26.10E`).
/// Requires a decimal point in at least one component to avoid matching pairs of
/// plain integers (e.g. ISSIs).
fn parse_decimal(text: &str) -> Option<LatLon> {
    // Collect signed decimal numbers with optional hemisphere suffix.
    let mut nums: Vec<(f64, Option<char>)> = Vec::new();
    let b = text.as_bytes();
    let mut i = 0;
    let mut saw_dot = false;
    while i < b.len() {
        let c = b[i] as char;
        if c == '-' || c == '+' || c.is_ascii_digit() {
            let start = i;
            i += 1;
            let mut local_dot = false;
            while i < b.len() {
                let d = b[i] as char;
                if d.is_ascii_digit() {
                    i += 1;
                } else if d == '.' && !local_dot {
                    local_dot = true;
                    saw_dot = true;
                    i += 1;
                } else {
                    break;
                }
            }
            if let Ok(v) = text.get(start..i).unwrap_or("").parse::<f64>() {
                // optional hemisphere letter
                let mut hemi = None;
                let mut j = i;
                while j < b.len() && (b[j] as char).is_ascii_whitespace() {
                    j += 1;
                }
                if j < b.len() {
                    match b[j] as char {
                        'N' | 'S' | 'E' | 'W' | 'n' | 's' | 'e' | 'w' => {
                            hemi = Some((b[j] as char).to_ascii_uppercase());
                            i = j + 1;
                        }
                        _ => {}
                    }
                }
                nums.push((v, hemi));
            }
        } else {
            i += 1;
        }
    }
    if !saw_dot || nums.len() < 2 {
        return None;
    }
    // Take the first two numbers as (lat, lon), applying hemisphere signs.
    let apply = |(v, h): (f64, Option<char>)| match h {
        Some('S') | Some('W') => -v.abs(),
        Some('N') | Some('E') => v.abs(),
        _ => v,
    };
    let lat = apply(nums[0]);
    let lon = apply(nums[1]);
    LatLon::new(lat, lon)
}

/// Maidenhead grid locator (4, 6, or 8 chars, e.g. `KN34bk`). Returns the
/// centre of the referenced square.
fn parse_maidenhead(text: &str) -> Option<LatLon> {
    // Scan whitespace-separated tokens for a valid locator.
    for tok in text.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        if let Some(ll) = maidenhead_token(tok) {
            return Some(ll);
        }
    }
    None
}

fn maidenhead_token(tok: &str) -> Option<LatLon> {
    let s = tok.trim();
    let n = s.len();
    if n != 4 && n != 6 && n != 8 {
        return None;
    }
    let c: Vec<char> = s.chars().collect();
    // Field: A-R, Square: 0-9, Subsquare: a-x, Extended square: 0-9
    let f0 = field_letter(c[0])?; // lon field 0..17
    let f1 = field_letter(c[1])?; // lat field 0..17
    let s0 = c[2].to_digit(10)? as f64; // lon square 0..9
    let s1 = c[3].to_digit(10)? as f64; // lat square 0..9

    let mut lon = -180.0 + f0 as f64 * 20.0 + s0 * 2.0;
    let mut lat = -90.0 + f1 as f64 * 10.0 + s1 * 1.0;
    // sizes of the current cell
    let mut lon_size = 2.0;
    let mut lat_size = 1.0;

    if n >= 6 {
        let ss0 = subsquare_letter(c[4])?; // 0..23
        let ss1 = subsquare_letter(c[5])?;
        lon += ss0 as f64 * (2.0 / 24.0);
        lat += ss1 as f64 * (1.0 / 24.0);
        lon_size = 2.0 / 24.0;
        lat_size = 1.0 / 24.0;
    }
    if n == 8 {
        let e0 = c[6].to_digit(10)? as f64; // 0..9
        let e1 = c[7].to_digit(10)? as f64;
        lon += e0 * (lon_size / 10.0);
        lat += e1 * (lat_size / 10.0);
        lon_size /= 10.0;
        lat_size /= 10.0;
    }
    // centre of the cell
    LatLon::new(lat + lat_size / 2.0, lon + lon_size / 2.0)
}

fn field_letter(c: char) -> Option<u8> {
    let u = c.to_ascii_uppercase();
    if ('A'..='R').contains(&u) {
        Some((u as u8) - b'A')
    } else {
        None
    }
}

fn subsquare_letter(c: char) -> Option<u8> {
    let l = c.to_ascii_lowercase();
    if ('a'..='x').contains(&l) {
        Some((l as u8) - b'a')
    } else {
        None
    }
}

/// Formats decimal-degrees latitude as APRS's uncompressed `DDMM.mmN`/`DDMM.mmS`
/// (the inverse of `aprs_lat_at`). Clamped to +/-90 first so a bad fix cannot
/// produce a malformed token.
pub fn format_aprs_lat(lat: f64) -> String {
    let lat = lat.clamp(-90.0, 90.0);
    let hemi = if lat < 0.0 { 'S' } else { 'N' };
    let abs = lat.abs();
    let deg = abs.floor() as u32;
    let min = (abs - deg as f64) * 60.0;
    format!("{deg:02}{min:05.2}{hemi}")
}

/// Formats decimal-degrees longitude as APRS's uncompressed `DDDMM.mmE`/`DDDMM.mmW`
/// (the inverse of `aprs_lon_at`).
pub fn format_aprs_lon(lon: f64) -> String {
    let lon = lon.clamp(-180.0, 180.0);
    let hemi = if lon < 0.0 { 'W' } else { 'E' };
    let abs = lon.abs();
    let deg = abs.floor() as u32;
    let min = (abs - deg as f64) * 60.0;
    format!("{deg:03}{min:05.2}{hemi}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < 0.01
    }

    #[test]
    fn zero_zero_is_never_a_position() {
        assert_eq!(parse_position("0.0, 0.0"), None);
        assert_eq!(parse_position("LIP position: 0.000000, 0.000000"), None);
        assert_eq!(parse_position("0000.00N 00000.00E"), None);
        assert!(parse_position("0.0, 23.7").is_some());
    }

    #[test]
    fn aprs_slash_symbol() {
        let p = parse_position("!4426.12N/02606.55E-").unwrap();
        assert!(approx(p.lat, 44.4353), "lat={}", p.lat);
        assert!(approx(p.lon, 26.1092), "lon={}", p.lon);
    }

    #[test]
    fn aprs_backslash_and_space() {
        let a = parse_position("4426.12N\\02606.55E").unwrap();
        let b = parse_position("4426.12N 02606.55E").unwrap();
        assert!(approx(a.lat, b.lat) && approx(a.lon, b.lon));
    }

    #[test]
    fn aprs_southern_western() {
        let p = parse_position("3350.00S 15112.00W").unwrap();
        assert!(p.lat < 0.0 && p.lon < 0.0);
        assert!(approx(p.lat, -33.8333), "lat={}", p.lat);
        assert!(approx(p.lon, -151.2), "lon={}", p.lon);
    }

    #[test]
    fn decimal_comma() {
        let p = parse_position("44.4353, 26.1092").unwrap();
        assert!(approx(p.lat, 44.4353) && approx(p.lon, 26.1092));
    }

    #[test]
    fn decimal_with_label_and_hemis() {
        let p = parse_position("POS 44.43N 26.10E").unwrap();
        assert!(approx(p.lat, 44.43) && approx(p.lon, 26.10));
    }

    #[test]
    fn decimal_negative() {
        let p = parse_position("-33.87, 151.21").unwrap();
        assert!(approx(p.lat, -33.87) && approx(p.lon, 151.21));
    }

    #[test]
    fn plain_integers_do_not_parse() {
        // pair of ISSIs must not be read as coordinates (no decimal point)
        assert!(parse_position("1001 2002").is_none());
    }

    #[test]
    fn maidenhead_6char() {
        // KN34bk ~ Bucharest area
        let p = parse_position("KN34bk").unwrap();
        assert!((44.0..45.0).contains(&p.lat), "lat={}", p.lat);
        assert!((25.0..27.0).contains(&p.lon), "lon={}", p.lon);
    }

    #[test]
    fn out_of_range_rejected() {
        assert!(parse_position("99.0, 200.0").is_none());
    }

    #[test]
    fn lip_short_report_real_sample() {
        // Live beacon captured from Basestation (ISSI 90), known to be in Athens.
        let bytes = [0x0a, 0x01, 0x0e, 0x62, 0x39, 0xb0, 0x43, 0x9a, 0xff, 0xe0, 0x20];
        let p = decode_lip(&bytes).expect("should decode short location report");
        assert!(approx(p.lat, 37.9920), "lat={}", p.lat);
        assert!(approx(p.lon, 23.7642), "lon={}", p.lon);
    }

    #[test]
    fn lip_hex_string_matches_bytes() {
        let a = decode_lip_hex("0a010e6239b0439affe020").unwrap();
        let b = decode_lip_hex("0a 01 0e 62 39 b0 43 9a ff e0 20").unwrap();
        assert!(approx(a.lat, b.lat) && approx(a.lon, b.lon));
        assert!(approx(a.lat, 37.9920));
    }

    #[test]
    fn lip_long_report_real_samples() {
        // Five live reports from a stationary MTH850 in Cholargos/Athens.
        // All must decode to ~37.9917 N, 23.7640 E.
        let samples = [
            "830011801313232f341f5c776dea66360868e310e616c15660",
            "8300128013132302341f5c776e0c663608688810e6193e5688",
            "830013801313232f341f5c776e40663608655510e60fe9563c",
            "83000d801313232f341f5c776d8c663608555510e61599568e",
            "83000a8013132302341f5c776d1766360865b010e62844561c",
        ];
        for s in samples {
            let bytes: Vec<u8> = (0..s.len()).step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
            let p = decode_lip_long(&bytes).expect("long report should decode");
            assert!((p.lat - 37.9917).abs() < 0.01, "lat={} for {s}", p.lat);
            assert!((p.lon - 23.7640).abs() < 0.01, "lon={} for {s}", p.lon);
        }
    }

    #[test]
    fn lip_long_rejects_non_83_and_short() {
        assert!(decode_lip_long(&[0x0a, 0x01, 0x0e]).is_none());
        assert!(decode_lip_long(&[0x83, 0x00]).is_none());
    }

    #[test]
    fn lip_no_fix_beacon_is_none() {
        // Real capture: a beacon with no GPS lock (all-zero lat/lon sentinel).
        // SDS data was 0a 30 00 00 00 00 00 07 ff e0 f0 -> must not plot.
        let bytes = [0x0a, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xff, 0xe0, 0xf0];
        assert!(decode_lip(&bytes).is_none(), "all-zero position must be rejected");
    }

    #[test]
    fn lip_rejects_non_lip_and_short() {
        assert!(decode_lip(&[0x82, 0x00, 0x01]).is_none(), "wrong PID");
        assert!(decode_lip(&[0x0a, 0x01]).is_none(), "too short");
        assert!(decode_lip(&[]).is_none());
    }

    #[test]
    fn empty_and_garbage() {
        assert!(parse_position("").is_none());
        assert!(parse_position("hello world").is_none());
        assert!(parse_position("status: OK").is_none());
    }

    #[test]
    fn format_aprs_lat_matches_known_value() {
        // 37.9917N (Athens) -> 37 deg + 0.9917*60 = 59.50 min
        assert_eq!(format_aprs_lat(37.9917), "3759.50N");
        assert_eq!(format_aprs_lat(-37.9917), "3759.50S");
    }

    #[test]
    fn format_aprs_lon_matches_known_value() {
        assert_eq!(format_aprs_lon(23.7640), "02345.84E");
        assert_eq!(format_aprs_lon(-23.7640), "02345.84W");
    }

    #[test]
    fn format_aprs_lat_lon_round_trips_through_the_parser() {
        let lat = 37.9917_f64;
        let lon = 23.7640_f64;
        let text = format!("!{}/{}>", format_aprs_lat(lat), format_aprs_lon(lon));
        let parsed = parse_aprs(&text).expect("should parse back");
        assert!(approx(parsed.lat, lat));
        assert!(approx(parsed.lon, lon));
    }
}
