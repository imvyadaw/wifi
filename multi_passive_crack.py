#!/usr/bin/env python3
"""
multi_passive_crack.py
Automates passive capture+crack for multiple OWNED APs (no active attacks).

Usage: sudo python3 multi_passive_crack.py

For each target: requires BSSID, channel, SSID (typed to confirm), and a wordlist path.
"""

import os, sys, time, subprocess, shlex
from datetime import datetime
from shutil import which

# ---------------- helpers ----------------
def check_program(name):
    if which(name) is None:
        print(f"[ERROR] Required program '{name}' not found. Install it (e.g. sudo apt install {name}) and retry.")
        return False
    return True

def run_stream(cmd):
    """Run command and stream stdout/stderr. Returns (returncode, full_output)."""
    print("+", " ".join(shlex.quote(x) for x in cmd))
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    except FileNotFoundError:
        return (127, f"Command not found: {cmd[0]}")
    out_lines = []
    for line in proc.stdout:
        line = line.rstrip("\n")
        out_lines.append(line)
        print(line)
    proc.wait()
    return (proc.returncode, "\n".join(out_lines))

def set_monitor(iface):
    print("[*] Setting interface into monitor mode (temporary)...")
    run_stream(["ip","link","set",iface,"down"])
    # try modern method
    rc, _ = run_stream(["iw","dev",iface,"set","type","monitor"])
    if rc != 0:
        print("[WARN] 'iw dev <iface> set type monitor' failed. You may need to use airmon-ng manually.")
    run_stream(["ip","link","set",iface,"up"])
    time.sleep(0.5)

def set_managed(iface):
    print("[*] Reverting interface to managed mode...")
    run_stream(["ip","link","set",iface,"down"])
    run_stream(["iw","dev",iface,"set","type","managed"])
    run_stream(["ip","link","set",iface,"up"])
    time.sleep(0.5)

def detect_handshake_with_aircrack(capfile, bssid):
    rc, out = run_stream(["aircrack-ng", capfile])
    out_low = out.lower()
    if "handshake" in out_low or "1 handshake" in out_low or "handshakes" in out_low:
        # basic heuristic, aircrack sometimes prints "1 handshake(s) found"
        return True
    # fallback scan: try to find bssid mentions in output
    if bssid.replace(":","").lower() in out_low.replace(":","").lower():
        return True
    return False

def attempt_crack_aircrack(capfile, bssid, wordlist):
    print(f"[*] Running aircrack-ng with wordlist {wordlist} on BSSID {bssid} ...")
    rc, out = run_stream(["aircrack-ng", "-w", wordlist, "-b", bssid, capfile])
    if "KEY FOUND!" in out:
        # aircrack prints KEY FOUND! with the key
        return True, out
    return False, out

def convert_to_hashcat(capfile, outname):
    # requires hcxpcapngtool
    if which("hcxpcapngtool") is None:
        print("[WARN] hcxpcapngtool not found; install hcxtools to convert to hashcat format.")
        return False
    rc, out = run_stream(["hcxpcapngtool", "-o", outname, capfile])
    return rc == 0

# ---------------- main logic ----------------
def main():
    print("MULTI PASSIVE CRACK (passive-only). Use only on your OWN networks.\n")

    # deps check
    for p in ("airodump-ng","aircrack-ng"):
        if not check_program(p):
            return

    iface = input("Enter wireless interface to use (e.g. wlan0): ").strip()
    if not iface:
        print("Interface required. Exiting.")
        return

    # how many APs
    try:
        n = int(input("How many targets (1-6)? Recommend 1-3: ").strip() or "1")
        if n < 1: n = 1
        if n > 6: n = 6
    except:
        n = 1

    targets = []
    for i in range(n):
        print(f"\n--- Target #{i+1} ---")
        b = input("BSSID (AA:BB:CC:DD:EE:FF): ").strip()
        ch = input("Channel (e.g. 6): ").strip()
        ssid = input("SSID (network name) (type EXACT to confirm ownership): ").strip()
        confirm = input("Type the SSID EXACTLY to confirm you own this network: ").strip()
        if confirm != ssid or not ssid:
            print("Confirmation mismatch. Skipping this target.")
            continue
        wl = input("Path to wordlist for this target (one password per line): ").strip()
        if not wl or not os.path.isfile(wl):
            print("Wordlist not found. Skipping this target.")
            continue
        dur = input("Capture duration in seconds (recommended 30-120): ").strip()
        try:
            dur = int(dur)
            if dur < 10:
                dur = 10
        except:
            dur = 60
        targets.append({"bssid": b, "chan": ch, "ssid": ssid, "wordlist": wl, "dur": dur})

    if not targets:
        print("No confirmed targets. Exiting.")
        return

    print("\nSummary of confirmed targets:")
    for t in targets:
        print(f" - {t['bssid']} (chan {t['chan']}) SSID={t['ssid']} wordlist={t['wordlist']} dur={t['dur']}s")
    ok = input("Type YES to proceed with passive captures for these targets: ").strip()
    if ok != "YES":
        print("Aborting.")
        return

    # Put interface to monitor mode once
    try:
        set_monitor(iface)
    except Exception as e:
        print("[WARN] Failed to set monitor mode cleanly:", e)

    try:
        for t in targets:
            bssid = t['bssid']
            chan = str(t['chan'])
            dur = int(t['dur'])
            prefix = f"auto_{bssid.replace(':','')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            capfile = f"{prefix}-01.cap"
            print(f"\n=== Processing {bssid} (chan {chan}) ===")
            print(f"[*] Passive capturing for {dur}s. If you want a handshake, temporarily disconnect & reconnect one of your OWN clients now.")
            # run airodump-ng with timeout
            cmd = ["timeout", str(dur), "airodump-ng", "--bssid", bssid, "-c", chan, "-w", prefix, iface]
            rc, out = run_stream(cmd)
            if not os.path.isfile(capfile):
                # try to find any cap files with prefix
                possible = [f for f in os.listdir(".") if f.startswith(prefix) and f.endswith(".cap")]
                if possible:
                    capfile = possible[0]
                    print(f"[INFO] Found cap file {capfile}")
                else:
                    print("[WARN] Capture file not found after capture. Skipping this target.")
                    continue
            print(f"[*] Capture saved to {capfile}. Checking for handshake...")
            has = detect_handshake_with_aircrack(capfile, bssid)
            if not has:
                print("[NOTICE] No handshake detected.")
                retry = input("Type 'retry' to run a short retry capture (you should toggle your client now), or press Enter to skip cracking: ").strip()
                if retry.lower() == "retry":
                    extra = input("Retry seconds (recommended 15-45): ").strip()
                    try:
                        extra = int(extra)
                        if extra < 5: extra = 15
                    except:
                        extra = 30
                    print(f"[*] Running retry passive capture for {extra}s. Toggle your client now.")
                    cmd = ["timeout", str(extra), "airodump-ng", "--bssid", bssid, "-c", chan, "-w", prefix, iface]
                    run_stream(cmd)
                    print("[*] Retry complete. Re-checking handshake...")
                    has = detect_handshake_with_aircrack(capfile, bssid)

            if not has:
                print("[X] Still no handshake present. Cannot attempt cracking for this target. Move to next.")
                continue

            # attempt cracking with aircrack-ng
            ok_found, out = attempt_crack_aircrack(capfile, bssid, t['wordlist'])
            if ok_found:
                print("[SUCCESS] Password recovered! See above output for KEY FOUND.")
            else:
                print("[INFO] aircrack-ng did not find the key with provided wordlist.")
                conv = input("Convert capture to hashcat format (.22000) for GPU cracking? (y/N): ").strip().lower()
                if conv == 'y':
                    outname = prefix + ".22000"
                    conv_ok = convert_to_hashcat(capfile, outname)
                    if conv_ok:
                        print(f"[OK] Converted to {outname}. Example hashcat command:\n  hashcat -m 22000 {outname} {t['wordlist']}")
                    else:
                        print("[WARN] Conversion failed or hcxpcapngtool missing.")
            # small pause between targets
            time.sleep(2)

    finally:
        try:
            set_managed(iface)
            print("[*] Interface reverted to managed mode.")
        except Exception as e:
            print("[WARN] Could not revert interface automatically:", e)

    print("\n[*] All done. Remember: only test your own networks.")
    
if __name__ == "__main__":
    main()
