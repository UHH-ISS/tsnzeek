# -----------------------------------------------------------
#
#  control.py
#
# The control channel between the IDS and the web interface: two JSON files in one directory.
#
#   state.json    written by the IDS: the rules with their state, the active configuration, counters
#   control.json  written by the web interface: {"disabled_rules": [...], "config": {"timeout": 30, ...}}
#
# The IDS polls control.json and applies it without a restart. A disabled rule keeps running, so that it knows the
# traffic when it is enabled again, but raises no alerts. A changed threshold replaces the config object of the
# detectors (`Detector.reconfigure`): one assignment, no rebuild, nothing they learned is lost. Nothing of this is on
# the packet path except the counters; the files are looked at about every half second, from the main loop.
# A file that does not validate is ignored as a whole and the reason is shown in state.json ("error").
#
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
# Released under GNU Public License (GPL)
# -----------------------------------------------------------
import collections
import json
import os
import time
from dataclasses import asdict, fields, replace

from .catalog import RULES, rule_name
from .config import Config

STATE = "state.json"
CONTROL = "control.json"


def validate(data, base: Config):
    """Return (disabled_rules, config) of a control.json, or raise ValueError saying what is wrong."""
    if not isinstance(data, dict):
        raise ValueError("control.json must be an object")
    unknown = set(data) - {"disabled_rules", "config"}
    if unknown:
        raise ValueError(f"unknown keys: {sorted(unknown)}")
    disabled = data.get("disabled_rules", [])
    if not isinstance(disabled, list):
        raise ValueError("disabled_rules must be a list of rule names or numbers")
    names = [rule_name(r) for r in disabled]
    bad = [r for r, n in zip(disabled, names) if n is None]
    if bad:
        raise ValueError(f"unknown rules: {bad}")
    disabled = names
    overrides = data.get("config", {})
    if not isinstance(overrides, dict):
        raise ValueError("config must be an object")
    known = {f.name: f for f in fields(Config)}
    if set(overrides) - set(known):
        raise ValueError(f"unknown config keys: {sorted(set(overrides) - set(known))}")
    clean = {}
    for key, value in overrides.items():
        kind = type(getattr(base, key))
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{key} must be a number")
        if value < 0:
            raise ValueError(f"{key} must not be negative")
        if kind is int and value != int(value):
            raise ValueError(f"{key} must be a whole number")
        clean[key] = kind(value)
    return set(disabled), replace(base, **clean)


class Control:
    def __init__(self, directory, base: Config, engine, info=None):
        self.dir = directory
        self.base = base
        self.config = base
        self.engine = engine
        self.info = info or {}
        self.error = None
        self.started = time.time()
        self.connected = False
        self.messages = collections.Counter()
        self.alerts = collections.Counter()
        self._mtime = None
        self._rate_at = (time.time(), collections.Counter())      # when and what the counters were at the last state
        self.rate = {}
        self._last_write = 0.0
        self._dirty = True
        os.makedirs(directory, exist_ok=True)

    # counters ---------------------------------------------------------------------------------------------------
    def note_message(self, kind):
        self.messages[kind] += 1

    def note_alerts(self, alerts):
        for a in alerts:
            self.alerts[a.rule] += 1
        if alerts:
            self._dirty = True

    def set_connected(self, connected):
        if connected != self.connected:
            self.connected, self._dirty = connected, True

    # the channel ------------------------------------------------------------------------------------------------
    def poll(self, now=None):
        """Apply control.json if it changed and refresh state.json (at most every two seconds, at once after a change)."""
        now = time.time() if now is None else now
        path = os.path.join(self.dir, CONTROL)
        try:
            st = os.stat(path)
            mtime = (st.st_ino, st.st_mtime_ns, st.st_size)     # the clock ticks coarsely; a replaced file has a new inode
        except FileNotFoundError:
            mtime = None
        if mtime != self._mtime:
            self._mtime = mtime
            self._apply(path if mtime is not None else None)
            self._dirty = True
        if self._dirty or now - self._last_write >= 2.0:
            self.write_state()
            self._last_write = now

    def _apply(self, path):
        if path is None:
            disabled, config, self.error = set(), self.base, None
        else:
            try:
                with open(path) as f:
                    disabled, config = validate(json.load(f), self.base)
                self.error = None
            except (ValueError, OSError) as e:       # json.JSONDecodeError is a ValueError
                self.error = f"control.json ignored: {e}"
                return
        if config != self.config:
            self.config = config
            for d in self.engine.detectors:
                d.reconfigure(config)
        self.engine.disabled = disabled

    def _streams(self, limit=200):
        merged = {}
        for d in self.engine.detectors:
            for protocol, rows in d.snapshot().items():
                merged.setdefault(protocol, []).extend(rows)
        return {p: rows[:limit] for p, rows in merged.items()}

    def write_state(self):
        now = time.time()
        then, before = self._rate_at
        if now - then >= 1.0:                                 # messages per second since the previous state
            self.rate = {k: round((self.messages[k] - before[k]) / (now - then), 1) for k in self.messages}
            self._rate_at = (now, collections.Counter(self.messages))
        defaults = asdict(Config())
        active = asdict(self.config)
        state = {
            "pid": os.getpid(), "started": self.started, "updated": time.time(), "connected": self.connected,
            "error": self.error, **self.info,
            "messages": dict(self.messages), "messages_per_second": self.rate, "streams": self._streams(),
            "rules": [{"id": r.id, "name": r.name, "protocol": r.protocol, "summary": r.summary, "thresholds": list(r.thresholds),
                       "enabled": r.name not in self.engine.disabled, "alerts": self.alerts[r.name]} for r in RULES],
            "config": {"active": active, "defaults": defaults,
                       "changed": sorted(k for k in active if active[k] != defaults[k])},
        }
        tmp = os.path.join(self.dir, STATE + ".tmp")
        with open(tmp, "w") as f:
            json.dump(state, f, indent=1)
        os.chmod(tmp, 0o644)
        os.replace(tmp, os.path.join(self.dir, STATE))
        self._dirty = False
