from flask import Flask, send_from_directory
from flask_cors import CORS
from src.routes.secure_routes import secure_bp

app = Flask(__name__, static_folder="static")
CORS(app)

app.register_blueprint(secure_bp, url_prefix="/api")

@app.route("/", methods=["GET"])
def home():
    """
    Serves the prototype UI.
    Same-origin eliminates CORS complexity.
    """
    return send_from_directory(app.static_folder, "index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

