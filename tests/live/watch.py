#!/usr/bin/env python3
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude

"""Follow Zeek's JSON logs in a directory and print one readable line per record, like `tail -f` for TSN.

    watch.py <log directory>
"""
import json
import os
import sys
import time

COLORS = {"cb": "36", "ptp": "32", "srp": "33", "tsn_errors": "31", "notice": "1;35"}
SHOWN = ("cb", "ptp", "srp", "tsn_errors", "notice")


def endpoint(addr, port):
    return f"[{addr}]:{port}" if ":" in str(addr) else f"{addr}:{port}"


def place(r):
    if "uid" in r:                                        # PTP over UDP: IP addresses and ports
        return f"{endpoint(r.get('src'), r.get('src_port'))} -> {endpoint(r.get('dst'), r.get('dst_port'))}"
    vlan = f" vlan {r['vlan']}" if "vlan" in r else ""
    return f"{r.get('src', '?')} -> {r.get('dst', '?')}{vlan}"


def render(log, r):
    if log == "cb":
        return f"CB     {place(r)}  seq={r['sequence_nr']}" + (f"  RESERVED={r['reserved']}" if r["reserved"] else "")
    if log == "ptp":
        extra = ""
        if "gm_priority1" in r:
            extra = f"  gm={r['gm_identity']} p1={r['gm_priority1']} class={r['gm_clock_class']}"
        elif "timestamp_sec" in r:
            extra = f"  t={r['timestamp_sec']}.{r['timestamp_ns']:09d}"
        return f"PTP    {place(r)}  {r['msg_type']} seq={r['sequence_id']} domain={r['domain_number']}{extra}"
    if log == "srp":
        want = ""
        if "interval_numerator" in r:
            want = (f"  {r['max_frames_per_interval']} x {r['max_frame_size']} B per "
                    f"{r['interval_numerator']}/{r['interval_denominator']} s")
        return f"SRP    {place(r)}  {r['msg_type']} stream={r['stream_mac']}/{r['stream_unique_id']}{want}"
    if log == "tsn_errors":
        return f"ERROR  {place(r)}  {r['protocol']}: {r['reason']}"
    return f"NOTICE {r.get('note', '')}: {r.get('msg', '')}"


def main(directory):
    offsets = {}
    print(f"watching {directory}  (cb / ptp / srp / tsn_errors / notice)\n", flush=True)
    while True:
        for log in SHOWN:
            path = os.path.join(directory, log + ".log")
            try:
                with open(path, "rb") as f:
                    f.seek(offsets.get(log, 0))
                    data = f.read()
            except FileNotFoundError:
                continue
            # Only complete lines: Zeek may still be writing the last one.
            complete = data[:data.rfind(b"\n") + 1]
            offsets[log] = offsets.get(log, 0) + len(complete)
            for line in complete.decode(errors="replace").splitlines():
                r = {}
                try:
                    r = json.loads(line)
                    text = render(log, r)
                except (ValueError, KeyError, TypeError) as e:
                    text = f"{log}: unreadable record ({e!r}): {line[:100]}"
                stamp = time.strftime("%H:%M:%S", time.localtime(r.get("ts", time.time())))
                print(f"\033[{COLORS[log]}m{stamp} {text}\033[0m", flush=True)
        time.sleep(0.2)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    try:
        main(sys.argv[1])
    except KeyboardInterrupt:
        pass
