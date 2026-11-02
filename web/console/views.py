# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
import json

from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_GET, require_POST

from . import store


@ensure_csrf_cookie                      # the page's script sends the token with every change
def index(request):
    return render(request, "console/index.html")


@require_GET
def api_state(request):
    return JsonResponse({**store.state(), "control": store.control(), "logs": store.log_names()})


def _body(request):
    try:
        data = json.loads(request.body or b"{}")
    except ValueError:
        raise ValueError("the body is not JSON")
    if not isinstance(data, dict):
        raise ValueError("the body must be an object")
    return data


def _change(request, action):
    try:
        return JsonResponse({"ok": True, "control": action(_body(request))})
    except ValueError as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=400)
    except OSError as e:
        return JsonResponse({"ok": False, "error": f"cannot write control.json: {e.strerror}"}, status=500)


@require_POST
def api_rule(request):
    """{"rule": "srp_request_burst" or 203, "enabled": false}"""
    def action(d):
        if not isinstance(d.get("enabled"), bool):
            raise ValueError("enabled must be true or false")
        return store.set_rule(d.get("rule"), d["enabled"])
    return _change(request, action)


@require_POST
def api_config(request):
    """{"set": {"timeout": 30}, "unset": ["frer_history_size"]}: unset goes back to the default."""
    def action(d):
        values, unset = d.get("set", {}), d.get("unset", [])
        if not isinstance(values, dict) or not isinstance(unset, list):
            raise ValueError("set must be an object and unset a list")
        return store.set_config(values, unset)
    return _change(request, action)


@require_POST
def api_reset(request):
    """Every rule enabled, every threshold at the value of the config file the IDS started with."""
    return _change(request, lambda d: store.reset())


@require_GET
def api_logs(request):
    name = request.GET.get("name", "")
    if name not in store.LOGS:
        return JsonResponse({"ok": False, "error": "unknown log"}, status=404)
    try:
        offset = int(request.GET.get("offset", "-1"))
    except ValueError:
        return JsonResponse({"ok": False, "error": "offset must be a number"}, status=400)
    lines, new = store.read_log(name, offset)
    return JsonResponse({"ok": True, "name": name, "lines": lines, "offset": new})
