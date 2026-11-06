# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
"""The files behind the web interface: state.json and control.json of the IDS, and Zeek's logs."""
import json
import os
import time

from django.conf import settings

from ids.catalog import rule_name
from ids.config import Config
from ids.control import CONTROL, STATE, validate

STALE_AFTER = 6.0          # seconds; the IDS rewrites state.json about every two
LOGS = {                   # name -> file (all JSON lines except alerts)
    "alerts": "alerts.log", "notice": "notice.log", "frer": "frer.log", "ptp": "ptp.log", "srp": "srp.log",
    "tsn_errors": "tsn_errors.log", "weird": "weird.log", "stats": "stats.log",
}
MAX_READ = 256 * 1024


def _read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def state():
    """state.json with its age; {"available": False} while the IDS has not written one."""
    path = settings.TSNZEEK_CONTROL_DIR / STATE
    data = _read_json(path)
    if data is None:
        return {"available": False, "control_dir": str(settings.TSNZEEK_CONTROL_DIR)}
    age = max(0.0, time.time() - data.get("updated", 0))
    return {"available": True, "stale": age > STALE_AFTER, "age": round(age, 1), "state": data}


def control():
    """The current control.json, or {} if there is none or it is unreadable."""
    data = _read_json(settings.TSNZEEK_CONTROL_DIR / CONTROL)
    return data if isinstance(data, dict) else {}


def write_control(data):
    """Validate, then replace control.json atomically (the IDS notices the new inode). Raises ValueError."""
    validate(data, Config())
    directory = settings.TSNZEEK_CONTROL_DIR
    os.makedirs(directory, exist_ok=True)
    tmp = directory / (CONTROL + ".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.chmod(tmp, 0o664)
    os.replace(tmp, directory / CONTROL)
    return data


def set_rule(ref, enabled):
    name = rule_name(ref)
    if name is None:
        raise ValueError(f"unknown rule: {ref}")
    data = control()
    disabled = {rule_name(r) for r in data.get("disabled_rules", [])} - {None}
    (disabled.discard if enabled else disabled.add)(name)
    data["disabled_rules"] = sorted(disabled)
    return write_control(data)


def set_config(values=None, unset=()):
    data = control()
    config = dict(data.get("config", {}))
    config.update(values or {})
    for key in unset:
        config.pop(key, None)
    data["config"] = config
    return write_control(data)


def reset():
    try:
        os.remove(settings.TSNZEEK_CONTROL_DIR / CONTROL)
    except FileNotFoundError:
        pass
    return {}


def log_names():
    return [n for n, f in LOGS.items() if (settings.TSNZEEK_LOG_DIR / f).is_file()]


def read_log(name, offset, tail=60):
    """New complete lines of a log since byte `offset` (-1: the last `tail` lines). Returns (lines, new offset)."""
    path = settings.TSNZEEK_LOG_DIR / LOGS[name]
    try:
        size = path.stat().st_size
    except OSError:
        return [], 0
    with open(path, "rb") as f:
        if offset < 0:
            start = max(0, size - MAX_READ)
            f.seek(start)
            lines = f.read(size - start).split(b"\n")
            if start:
                lines = lines[1:]                          # the first line may be cut
            complete = lines[:-1]
            consumed = size - len(lines[-1])
            lines = complete[-tail:]
            return [l.decode("utf-8", "replace") for l in lines if l], consumed
        if offset > size:                                  # rotated or truncated: start over
            offset = 0
        f.seek(offset)
        chunk = f.read(min(size - offset, MAX_READ))
    end = chunk.rfind(b"\n") + 1                           # only whole lines; a partial one is read next time
    lines = chunk[:end].decode("utf-8", "replace").split("\n")
    return [l for l in lines if l], offset + end
