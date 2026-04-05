from flask import Blueprint, request, jsonify, render_template_string
import random
import time
from datetime import datetime


sim_backend = Blueprint("sim_backend", __name__, url_prefix="/backend")


@sim_backend.route("/")
def backend_index():
    return jsonify({
        "message": "PhantomWall Simulated Backend API",
        "endpoints": [
            "/backend/login - Simulated login endpoint",
            "/backend/search - Simulated search endpoint",
            "/backend/users - User management",
            "/backend/admin - Admin panel",
            "/backend/upload - File upload simulation",
            "/backend/api/data - Data API"
        ]
    })


@sim_backend.route("/login", methods=["POST", "GET"])
def simulated_login():
    if request.method == "GET":
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head><title>Simulated Login</title></head>
        <body>
            <h1>Simulated Login Form</h1>
            <form method="POST">
                <input type="text" name="username" placeholder="Username" /><br>
                <input type="password" name="password" placeholder="Password" /><br>
                <button type="submit">Login</button>
            </form>
            <p>Try SQL injection: admin' OR '1'='1</p>
        </body>
        </html>
        """)
    
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    
    return jsonify({
        "status": "processed",
        "username_received": username,
        "password_length": len(password) if password else 0,
        "message": "Login request received (simulated backend - no actual authentication)",
        "timestamp": datetime.now().isoformat()
    })


@sim_backend.route("/search")
def simulated_search():
    query = request.args.get("q", "")
    
    simulated_results = [
        {"id": 1, "title": "Product A", "description": "A great product"},
        {"id": 2, "title": "Product B", "description": "Another product"},
        {"id": 3, "title": "Article about Security", "description": "Security best practices"},
    ]
    
    return jsonify({
        "query": query,
        "results": simulated_results,
        "count": len(simulated_results),
        "message": "Search completed (simulated backend)"
    })


@sim_backend.route("/users", methods=["GET", "POST"])
def simulated_users():
    if request.method == "POST":
        data = request.get_json() or request.form
        return jsonify({
            "action": "create_user",
            "data_received": dict(data),
            "user_id": random.randint(1000, 9999),
            "message": "User creation simulated"
        })
    
    users = [
        {"id": 1, "name": "Alice", "role": "user"},
        {"id": 2, "name": "Bob", "role": "user"},
        {"id": 3, "name": "Charlie", "role": "admin"},
    ]
    
    return jsonify({"users": users, "count": len(users)})


@sim_backend.route("/admin")
def simulated_admin():
    action = request.args.get("action", "dashboard")
    
    return jsonify({
        "panel": "admin",
        "action": action,
        "data": {
            "system_status": "running",
            "users_online": random.randint(5, 50),
            "last_backup": "2024-01-15 03:00:00"
        },
        "message": "Admin panel accessed (simulated)"
    })


@sim_backend.route("/upload", methods=["POST"])
def simulated_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files["file"]
    filename = file.filename
    
    return jsonify({
        "filename": filename,
        "size": random.randint(1000, 1000000),
        "uploaded": True,
        "message": "File upload simulated (no actual file stored)"
    })


@sim_backend.route("/api/data")
def simulated_api_data():
    data_type = request.args.get("type", "general")
    
    datasets = {
        "general": {"items": list(range(1, 11)), "meta": {"total": 10}},
        "users": {"count": 150, "active": 120, "new_today": 5},
        "sales": {"daily": random.randint(1000, 5000), "monthly": random.randint(30000, 150000)},
        "logs": {"entries": [], "count": 0}
    }
    
    return jsonify({
        "type": data_type,
        "data": datasets.get(data_type, datasets["general"]),
        "timestamp": datetime.now().isoformat()
    })


@sim_backend.route("/cmd", methods=["POST"])
def simulated_command():
    command = request.form.get("cmd", "")
    
    return jsonify({
        "command_received": command,
        "output": "Command execution simulated - no actual command was run",
        "exit_code": 0,
        "execution_time": 0.001,
        "warning": "This is a simulated endpoint for WAF testing"
    })


@sim_backend.route("/config")
def simulated_config():
    return jsonify({
        "database": "mysql://localhost:3306/app_db",
        "debug": False,
        "secret_key": "simulated-secret-key-do-not-use",
        "api_keys": {"service_a": "key_12345", "service_b": "key_67890"},
        "warning": "This endpoint exposes configuration for testing purposes"
    })


@sim_backend.route("/debug")
def simulated_debug():
    return jsonify({
        "environment": "development",
        "traceback": None,
        "request_info": {
            "method": request.method,
            "path": request.path,
            "args": dict(request.args),
            "headers": dict(request.headers)
        },
        "server_info": {
            "version": "1.0.0",
            "python": "3.10",
            "framework": "Flask"
        }
    })


@sim_backend.route("/error")
def simulated_error():
    error_type = request.args.get("type", "500")
    
    error_responses = {
        "500": ({"error": "Internal Server Error", "traceback": "simulated_traceback_here"}, 500),
        "404": ({"error": "Not Found", "message": "Resource does not exist"}, 404),
        "403": ({"error": "Forbidden", "message": "Access denied"}, 403),
        "401": ({"error": "Unauthorized", "message": "Authentication required"}, 401)
    }
    
    response, code = error_responses.get(error_type, error_responses["500"])
    return jsonify(response), code
