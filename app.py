import os
import re
import smtplib
import secrets
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


# ==========================================
# Flask App
# ==========================================

app = Flask(__name__)


# ==========================================
# Environment Variables
# ==========================================

GMAIL = os.environ.get("GMAIL")
APP_PASSWORD = os.environ.get("APP_PASSWORD")
API_KEY = os.environ.get("API_KEY")


# ==========================================
# Check Environment Variables
# ==========================================

if not GMAIL:
    print("WARNING: GMAIL environment variable is missing")

if not APP_PASSWORD:
    print("WARNING: APP_PASSWORD environment variable is missing")

if not API_KEY:
    print("WARNING: API_KEY environment variable is missing")


# ==========================================
# Rate Limiter
# ==========================================

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)


# ==========================================
# Email Validation
# ==========================================

def valid_email(email):

    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    return re.match(pattern, email) is not None


# ==========================================
# Send OTP Email
# ==========================================

def send_otp_email(receiver, otp):

    subject = "Your OTP Verification Code"

    html = f"""
    <!DOCTYPE html>

    <html>

    <head>
        <meta charset="UTF-8">
        <title>OTP Verification</title>
    </head>

    <body style="
        margin:0;
        padding:0;
        background:#f2f4f7;
        font-family:Arial,Helvetica,sans-serif;
    ">

        <div style="
            max-width:500px;
            margin:40px auto;
            background:#ffffff;
            border-radius:15px;
            padding:35px;
            text-align:center;
            box-shadow:0 4px 15px rgba(0,0,0,0.08);
        ">

            <h2 style="
                margin-bottom:10px;
                color:#222;
            ">
                OTP Verification
            </h2>

            <p style="
                color:#555;
                font-size:15px;
            ">
                Your verification code is:
            </p>

            <div style="
                margin:25px 0;
                padding:18px;
                background:#f5f5f5;
                border-radius:10px;
                font-size:32px;
                font-weight:bold;
                letter-spacing:8px;
                color:#111;
            ">
                {otp}
            </div>

            <p style="
                color:#777;
                font-size:14px;
            ">
                Please do not share this OTP with anyone.
            </p>

            <p style="
                color:#999;
                font-size:12px;
                margin-top:25px;
            ">
                If you did not request this code,
                you can safely ignore this email.
            </p>

        </div>

    </body>

    </html>
    """

    message = MIMEMultipart("alternative")

    message["From"] = GMAIL
    message["To"] = receiver
    message["Subject"] = subject

    message.attach(
        MIMEText(html, "html", "utf-8")
    )

    # ======================================
    # Gmail SMTP
    # ======================================

    with smtplib.SMTP(
        "smtp.gmail.com",
        587,
        timeout=30
    ) as server:

        server.ehlo()

        server.starttls()

        server.ehlo()

        server.login(
            GMAIL,
            APP_PASSWORD
        )

        server.sendmail(
            GMAIL,
            receiver,
            message.as_string()
        )


# ==========================================
# Send OTP API
# ==========================================

@app.route("/send_otp", methods=["GET"])
@limiter.limit("10 per minute")
def send_otp():

    # --------------------------------------
    # Check API Key
    # --------------------------------------

    api_key = request.args.get("api_key")

    if not API_KEY:

        return jsonify({
            "success": False,
            "error": "Server API key is not configured"
        }), 500


    if not api_key:

        return jsonify({
            "success": False,
            "error": "API key is required"
        }), 401


    try:

        if not secrets.compare_digest(
            api_key,
            API_KEY
        ):

            return jsonify({
                "success": False,
                "error": "Invalid API key"
            }), 401

    except Exception:

        return jsonify({
            "success": False,
            "error": "Invalid API key"
        }), 401


    # --------------------------------------
    # Get Parameters
    # --------------------------------------

    otp = request.args.get("otp")
    receiver = request.args.get("gmail")


    # --------------------------------------
    # Validate OTP
    # --------------------------------------

    if not otp:

        return jsonify({
            "success": False,
            "error": "OTP is required"
        }), 400


    if not otp.isdigit():

        return jsonify({
            "success": False,
            "error": "OTP must contain numbers only"
        }), 400


    if len(otp) < 4 or len(otp) > 8:

        return jsonify({
            "success": False,
            "error": "OTP must contain 4-8 digits"
        }), 400


    # --------------------------------------
    # Validate Receiver
    # --------------------------------------

    if not receiver:

        return jsonify({
            "success": False,
            "error": "Gmail is required"
        }), 400


    receiver = receiver.strip()


    if not valid_email(receiver):

        return jsonify({
            "success": False,
            "error": "Invalid email address"
        }), 400


    # --------------------------------------
    # Check Gmail Configuration
    # --------------------------------------

    if not GMAIL or not APP_PASSWORD:

        return jsonify({
            "success": False,
            "error": "Mail server is not configured"
        }), 500


    # --------------------------------------
    # Send Email
    # --------------------------------------

    try:

        send_otp_email(
            receiver,
            otp
        )

        print(
            f"OTP email sent successfully to {receiver}"
        )

        return jsonify({
            "success": True,
            "message": "OTP sent successfully",
            "to": receiver
        })


    except smtplib.SMTPAuthenticationError as e:

        print(
            "SMTP AUTH ERROR:",
            repr(e)
        )

        return jsonify({
            "success": False,
            "error": "Gmail authentication failed"
        }), 500


    except smtplib.SMTPConnectError as e:

        print(
            "SMTP CONNECTION ERROR:",
            repr(e)
        )

        return jsonify({
            "success": False,
            "error": "Could not connect to Gmail SMTP"
        }), 500


    except smtplib.SMTPException as e:

        print(
            "SMTP ERROR:",
            repr(e)
        )

        return jsonify({
            "success": False,
            "error": "Gmail SMTP error"
        }), 500


    except Exception as e:

        print(
            "EMAIL ERROR:",
            repr(e)
        )

        return jsonify({
            "success": False,
            "error": "Failed to send email"
        }), 500


# ==========================================
# Home
# ==========================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "success": True,
        "status": "online",
        "service": "OTP Mail API"
    })


# ==========================================
# Health Check
# ==========================================

@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "healthy"
    })


# ==========================================
# Run
# ==========================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )