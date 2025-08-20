from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest
from crawling import crawl_and_parse

app = Flask(__name__)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/crawl", methods=["POST"])
def crawl():
    """
    Body(JSON):
    {
      "target_url": "https://example.com",
      "cookies": {"sid":"abc..."},
      "max_depth": 2
    }
    """
    if not request.is_json:
        raise BadRequest("Content-Type must be application/json")

    payload = request.get_json(silent=True) or {}
    target_url = payload.get("target_url")
    if not target_url:
        raise BadRequest("'target_url' is required")

    api_input = {
        "target_url": target_url,
        "cookies": payload.get("cookies", {}),
        "max_depth": int(payload.get("max_depth", 0)),
    }
    
    result = crawl_and_parse(api_input)

    status_code = 200 if "error" not in result else 500
    return jsonify(result), status_code


# 로컬 개발 실행
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
