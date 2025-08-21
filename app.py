import os
import threading
import traceback
import time
import platform
import requests
from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest
from crawling import crawl_and_parse

# Configuration from environment
CONTROLLER_URL = os.environ.get("CONTROLLER_URL", "http://localhost:5000").rstrip('/')
CALLBACK_PRIMARY = f"{CONTROLLER_URL}/api/v1/internal/task/complete"
CALLBACK_FALLBACK = f"{CONTROLLER_URL}/internal/task/complete"  # legacy
SERVICE_NAME = "crawler"
DEFAULT_PORT = int(os.environ.get("PORT", os.environ.get("CRAWLER_PORT", "5001")))
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "25"))

app = Flask(__name__)

APP_VERSION = "1.0.0"


def _basic_health_payload():
    """Collect lightweight health info (no webdriver launch)."""
    try:
        import selenium  # noqa: WPS433
        from bs4 import __version__ as bs_version  # noqa: WPS433
        sel_ver = selenium.__version__
    except Exception:  # noqa: BLE001
        sel_ver = "unknown"
        bs_version = "unknown"
    return {
        "status": "ok",
        "service": SERVICE_NAME,
        "version": APP_VERSION,
        "time": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        "python": platform.python_version(),
        "selenium": sel_ver,
        "beautifulsoup4": bs_version,
        "threads_active": threading.active_count(),
        "controller_callback_primary": CALLBACK_PRIMARY,
    }


@app.route("/health", methods=["GET"])
def health():
    """Lightweight liveness probe."""
    return jsonify(_basic_health_payload()), 200


@app.route("/system/health", methods=["GET"])
def system_health():
    """More detailed health (still lightweight; no real crawl)."""
    payload = _basic_health_payload()
    # Add environment-derived config snapshot
    payload["config"] = {
        "PORT": DEFAULT_PORT,
        "REQUEST_TIMEOUT": REQUEST_TIMEOUT,
        "CONTROLLER_URL": CONTROLLER_URL,
    }
    return jsonify(payload), 200

def _post_callback(payload: dict):
    """Send task completion callback to controller with fallback path."""
    for url in (CALLBACK_PRIMARY, CALLBACK_FALLBACK):
        try:
            resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
            if resp.status_code < 300:
                return True, url, resp.status_code
            last_err = f"status={resp.status_code} body={resp.text[:200]}"
        except Exception as e:  # noqa: BLE001
            last_err = str(e)
    app.logger.error(f"Callback failed after retries: {last_err}")
    return False, CALLBACK_FALLBACK, None


def _run_crawl_async(task_guid: str, api_input: dict):
    """Worker thread performing the crawl, then calling back controller."""
    parent_guid = api_input.get("parent_guid")
    target_url = api_input.get("target_url", "unknown")
    
    try:
        app.logger.info(f"Starting crawl task {task_guid} for {target_url}")
        result = crawl_and_parse(api_input)
        
        # Check if crawling was successful
        if "error" not in result and "url" in result:
            status = "completed"
            callback_payload = {
                "guid": task_guid,
                "parent_guid": parent_guid,
                "service_name": SERVICE_NAME,
                "status": status,
                "result_data": result,
                "error_message": None,
            }
            app.logger.info(f"Crawl task {task_guid} completed successfully for {result.get('url')}")
        else:
            status = "failed"
            error_msg = result.get("error", "Unknown crawl error")
            callback_payload = {
                "guid": task_guid,
                "parent_guid": parent_guid,
                "service_name": SERVICE_NAME,
                "status": status,
                "result_data": None,
                "error_message": error_msg,
            }
            app.logger.error(f"Crawl task {task_guid} failed: {error_msg}")
            
    except Exception as e:  # noqa: BLE001
        tb = traceback.format_exc()
        app.logger.error(f"Unexpected crawl failure for {target_url}: {e}\n{tb}")
        callback_payload = {
            "guid": task_guid,
            "parent_guid": parent_guid,
            "service_name": SERVICE_NAME,
            "status": "failed",
            "error_message": f"Unexpected error: {str(e)}",
        }
    
    # Send callback
    success, callback_url, status_code = _post_callback(callback_payload)
    if success:
        app.logger.info(f"Successfully sent callback for task {task_guid} to {callback_url}")
    else:
        app.logger.error(f"Failed to send callback for task {task_guid} - controller may not receive completion notice")


@app.route("/crawl", methods=["POST"])
def crawl():  # noqa: D401
    """Trigger a crawl task.

    Body(JSON):
    {
      "task_guid": "<uuid>",          # required
      "parent_guid": "<uuid>",        # required
      "target_url": "https://...",    # required
      "cookies": {"sid":"abc"},      # optional
      "max_depth": 2,                  # optional (legacy)
      "remaining_depth": 2,            # optional (preferred)
      "current_depth": 0               # optional
    }
    Returns 200 immediately after accepting task, real result via callback.
    """
    if not request.is_json:
        raise BadRequest("Content-Type must be application/json")

    payload = request.get_json(silent=True) or {}
    required = ["task_guid", "parent_guid", "target_url"]
    missing = [f for f in required if not payload.get(f)]
    if missing:
        raise BadRequest(f"Missing required fields: {', '.join(missing)}")

    # Normalize / map fields
    api_input = {
        "parent_guid": payload["parent_guid"],
        "target_url": payload["target_url"],
        "cookies": payload.get("cookies", {}),
        "max_depth": int(payload.get("max_depth", 0)),
        "remaining_depth": int(payload.get("remaining_depth", payload.get("max_depth", 0))),
        "current_depth": int(payload.get("current_depth", 0)),
    }

    thread = threading.Thread(target=_run_crawl_async, args=(payload["task_guid"], api_input), daemon=True)
    thread.start()

    return jsonify({
        "status": "accepted",
        "task_guid": payload["task_guid"],
        "parent_guid": payload["parent_guid"],
        "target_url": payload["target_url"],
        "callback": CALLBACK_PRIMARY,
    }), 200


# 로컬 개발 실행
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=DEFAULT_PORT, debug=False)
