#!/usr/bin/env python3
import argparse
import os
import re
import sys
import yaml
from datetime import datetime, timezone
from OTXv2 import OTXv2, IndicatorTypes, BadRequest

def load_config(path):
    """Load YAML configuration from the given path."""
    with open(path) as f:
        return yaml.safe_load(f)

def sanitize_pulse_name(name: str) -> str:
    """
    Turn a pulse name like "FortiGate VPN-SSL Honeypot"
    into a filesystem-safe string, e.g. "FortiGate_VPN_SSL_Honeypot".
    You can tweak this regex if you want to allow other characters.
    """
    # Replace any sequence of characters that is not A–Z, a–z, 0–9 with underscore.
    return re.sub(r'[^A-Za-z0-9]+', '_', name).strip('_')

def get_state_file_path(pulse_name: str) -> str:
    """
    Given the pulse name, return a path under otx_config such as:
      "./report_to_otx/otx_config/state_<sanitized_pulse_name>.txt"
    """
    sanitized = sanitize_pulse_name(pulse_name)
    # __file__ is something like ".../report_to_otx/report_to_otx.py"
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, "otx_config", f"state_{sanitized}.txt")

def load_last_reported(state_file: str) -> datetime:
    """
    Read the last-reported datetime from state_file.
    If it doesn't exist or is invalid, return epoch (UTC).
    """
    if os.path.exists(state_file):
        content = open(state_file, "r").read().strip()
        try:
            # We expect an ISO-8601 string like "2025-05-28T04:26:13+00:00"
            return datetime.fromisoformat(content)
        except ValueError:
            # Fall through to return epoch if parsing fails
            pass

    # Default to epoch UTC if file missing or unparsable
    return datetime(1970, 1, 1, tzinfo=timezone.utc)

def save_last_reported(state_file: str, timestamp: datetime) -> None:
    """
    Overwrite state_file with the new ISO-formatted timestamp.
    Creates parent directories if needed.
    """
    os.makedirs(os.path.dirname(state_file), exist_ok=True)
    with open(state_file, "w") as f:
        # Write e.g. "2025-05-28T04:26:13+00:00"
        f.write(timestamp.isoformat())

def parse_honeypot_bad_ips(cfg: dict, last_dt: datetime) -> list:
    """
    Read the `ip_file` defined under cfg['honeypot']['ip_file'].
    Return a list of (ip, datetime) tuples for any entries > last_dt.
    Each line in ip_file must be: "<ip>,<ISO8601-timestamp>"
    """
    ip_file = cfg['honeypot']['ip_file']
    new_entries = []
    with open(ip_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:    
                ip, raw_ts = line.split("\t", 1)
            except ValueError:
                continue   
            try:
                dt = datetime.fromisoformat(raw_ts)
            except ValueError:
                # Skip lines that are not well‐formed
                continue 
            if dt > last_dt:
                new_entries.append((ip, dt))
    return new_entries

def get_my_pulse_id(otx: OTXv2, name: str):
    """
    If a pulse with the given name already exists in your OTX account,
    return its ID. Otherwise, return None.
    """
    resp = otx.get_my_pulses(query="")
    for pulse in resp:
        if pulse.get("name") == name:
            return pulse["id"]
    return None

def create_pulse(otx: OTXv2, cfg: dict, ips: list):
    """
    Create a new OTX Pulse with the name cfg['pulse']['name'] and other
    settings, then add all IP indicators in `ips`. Return the new pulse ID.
    """
    p = cfg["pulse"]

    indicators = [{"indicator": ip, "type": "IPv4"} for ip in ips]

    # Create the pulse itself
    try:
        resp = otx.create_pulse(
            name=p["name"],
            description=p["description"],
            public=p["public"],
            tlp=p["tlp"],
            pulse_type=p["type"],
            indicators=indicators
            )
        pulse_id = resp.get("id")
    except BadRequest:
        print("Error trying to report to OTX: BadRequest")    

    return pulse_id

def sync_pulse_indicators(otx: OTXv2, pulse_id: str, ips: list):
    """
    Given an existing pulse_id, fetch all existing indicators. Then add only
    those from `ips` that are not already present.
    """
    existing_indicators = set(
        i['indicator'] for i in otx.get_pulse_indicators(pulse_id)
    )
    for ip, dt in ips:
        if ip not in existing_indicators:
            indicator = {
                "type":      "IPv4",
                "indicator": ip
            }
            try:
                otx.add_pulse_indicators(pulse_id, indicator)
            except BadRequest:
                print("Error trying to report to OTX: BadRequest")

def main():
    parser = argparse.ArgumentParser(description="Sync honeypot IPs into an OTX Pulse")
    parser.add_argument("-c", "--config",
                        help="path to YAML config")
    args = parser.parse_args()

    # 1) Load YAML config
    cfg = load_config(args.config)

    # 2) Build a dynamic state file name based on the pulse name
    pulse_name = cfg['pulse']['name']
    state_file = get_state_file_path(pulse_name)
    #    e.g. state_file == "./report_to_otx/otx_config/state_FortiGate_VPN_SSL_Honeypot.txt"

    # 3) Instantiate OTX client
    otx = OTXv2(cfg['otx']['api_key'])

    # 4) Determine which IPs to report (only those after state_file timestamp)
    last_dt = load_last_reported(state_file)
    new_entries = parse_honeypot_bad_ips(cfg, last_dt)

    ips = [ip for ip, _ in new_entries]

    if not new_entries:
        print(f"No new IPs to report. Last state at {last_dt}")
        sys.exit(0)

    # 5) Create or sync the OTX pulse
    pulse_id = get_my_pulse_id(otx, pulse_name)
    if pulse_id:
        print(f"Found existing pulse ID={pulse_id}, syncing indicators...")
        sync_pulse_indicators(otx, pulse_id, new_entries)
    else:
        print("Pulse not found; creating new one with initial indicators...")
        pulse_id = create_pulse(otx, cfg, ips)
        print(f"Created pulse ID={pulse_id}")

    # 6) Save the new “last reported” timestamp (the max of all new entries)
    newest_dt = max(dt for _, dt in new_entries)
    save_last_reported(state_file, newest_dt)
    print(f"Updated state file: {state_file} → {newest_dt.isoformat()}")


if __name__ == "__main__":
    main()
