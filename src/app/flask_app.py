"""
Flask application for Network Device Inventory.
"""
import asyncio
import logging
import os
from datetime import timedelta
from functools import wraps

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from werkzeug.security import check_password_hash

# Configure logging
log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

from src.config.settings import get_settings
from src.core.ip_utils import is_valid_ip, parse_targets, estimate_target_count
from src.core.job_tracker import get_job_tracker
from src.core.scanner import DeviceScanner
from src.credentials import get_credential_provider
from src.credentials.models import SNMPv2cProfile, SNMPv3Profile
from src.db.connection import get_db_session, init_db
from src.db.repositories.device import DeviceRepository
from src.db.repositories.scan import ScanHistoryRepository
from src.db.repositories.nautobot_sync import NautobotSyncRepository
from src.scheduler import get_scheduler
from src.snmp.client import AuthProtocol, PrivProtocol

# Initialize Flask app
settings = get_settings()
app = Flask(__name__)
app.secret_key = settings.secret_key
app.permanent_session_lifetime = timedelta(hours=settings.session_lifetime_hours)

# Initialize database and scheduler on app startup
_app_initialized = False


def init_app():
    """Initialize the app (database, scheduler) - called once on first request."""
    global _app_initialized
    if not _app_initialized:
        # Initialize database tables
        init_db()
        # Start scheduler
        scheduler = get_scheduler()
        scheduler.start()
        _app_initialized = True


@app.before_request
def before_request():
    """Run before each request."""
    init_app()


def run_async(coro):
    """Run async coroutine in sync context."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ============== Authentication ==============

def login_required(f):
    """Decorator to require login for a view."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        settings = get_settings()
        # Skip auth check if auth is disabled
        if not settings.auth_enabled:
            return f(*args, **kwargs)
        # Check if user is logged in
        if not session.get("logged_in"):
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def api_login_required(f):
    """Decorator to require login for API endpoints (returns JSON error)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        settings = get_settings()
        # Skip auth check if auth is disabled
        if not settings.auth_enabled:
            return f(*args, **kwargs)
        # Check if user is logged in
        if not session.get("logged_in"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page."""
    settings = get_settings()

    # If auth is disabled, redirect to dashboard
    if not settings.auth_enabled:
        return redirect(url_for("dashboard"))

    # If already logged in, redirect to dashboard or next URL
    if session.get("logged_in"):
        next_url = request.args.get("next")
        return redirect(next_url or url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Check credentials against settings
        # auth_password_hash can be plaintext (for dev) or werkzeug hash (for prod)
        password_valid = False
        if settings.auth_password_hash.startswith("pbkdf2:") or settings.auth_password_hash.startswith("scrypt:"):
            # It's a hash - use check_password_hash
            password_valid = check_password_hash(settings.auth_password_hash, password)
        else:
            # It's plaintext - direct comparison
            password_valid = password == settings.auth_password_hash

        if username == settings.auth_username and password_valid:
            session["logged_in"] = True
            session["username"] = username
            session.permanent = True
            flash("Login successful!", "success")

            # Redirect to original destination or dashboard
            next_url = request.args.get("next")
            return redirect(next_url or url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Logout the user."""
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.context_processor
def inject_auth_context():
    """Inject authentication context into all templates."""
    settings = get_settings()
    return {
        "auth_enabled": settings.auth_enabled,
        "current_user": session.get("username") if session.get("logged_in") else None,
    }


# ============== Dashboard ==============

@app.route("/")
@login_required
def dashboard():
    """Main dashboard page."""
    stats = {
        "total_devices": 0,
        "active_devices": 0,
        "vendors": [],
        "scan_stats": {"total": 0, "success": 0, "failed": 0, "success_rate": 0},
        "recent_scans": [],
    }

    try:
        with get_db_session() as session:
            device_repo = DeviceRepository(session)
            scan_repo = ScanHistoryRepository(session)

            stats["total_devices"] = device_repo.count()
            stats["active_devices"] = device_repo.count(is_active=True)
            stats["vendors"] = device_repo.get_vendors()
            stats["scan_stats"] = scan_repo.get_stats()
            stats["recent_scans"] = scan_repo.get_recent(limit=10)
    except Exception as e:
        flash(f"Database connection error: {e}", "warning")

    return render_template("dashboard.html", stats=stats)


# ============== Single Scan ==============

@app.route("/scan", methods=["GET", "POST"])
@login_required
def single_scan():
    """Single device scan page."""
    cred_provider = get_credential_provider()
    profiles = run_async(cred_provider.list_profiles())
    result = None
    error = None

    if request.method == "POST":
        ip_address = request.form.get("ip_address", "").strip()
        profile_name = request.form.get("profile")
        port = int(request.form.get("port", 161))
        timeout = int(request.form.get("timeout", 5))
        retries = int(request.form.get("retries", 2))

        if not ip_address:
            error = "IP address is required"
        elif not is_valid_ip(ip_address):
            error = "Invalid IP address format"
        elif not profile_name:
            error = "Please select a credential profile"
        else:
            try:
                scanner = DeviceScanner(timeout=timeout, retries=retries)

                # Handle auto-discover mode
                if profile_name == "__auto__":
                    all_profiles = run_async(cred_provider.get_all_profiles_ordered())
                    if not all_profiles:
                        error = "No credential profiles configured"
                    else:
                        scan_result = run_async(
                            scanner.scan_device_auto_discover(
                                ip_address=ip_address,
                                profiles=all_profiles,
                                port=port,
                                scan_type="single",
                            )
                        )
                        result = scan_result
                        if scan_result.success:
                            flash(f"Scan completed successfully using profile '{scan_result.credential_profile_name}'!", "success")
                        else:
                            error = scan_result.error
                else:
                    # Single profile mode
                    profile = run_async(cred_provider.get_profile(profile_name))
                    if not profile:
                        error = f"Profile '{profile_name}' not found"
                    else:
                        scan_result = run_async(
                            scanner.scan_device(
                                ip_address=ip_address,
                                credential=profile.to_snmp_credential(),
                                port=port,
                                scan_type="single",
                                credential_profile_name=profile_name,
                            )
                        )
                        result = scan_result
                        if scan_result.success:
                            flash("Scan completed successfully!", "success")
                        else:
                            error = scan_result.error
            except Exception as e:
                error = str(e)

    return render_template(
        "scan.html", profiles=profiles, result=result, error=error
    )


# ============== Batch Scan ==============

@app.route("/batch", methods=["GET", "POST"])
@login_required
def batch_scan():
    """Batch scan page."""
    import threading

    cred_provider = get_credential_provider()
    profiles = run_async(cred_provider.list_profiles())
    error = None

    if request.method == "POST":
        targets_text = request.form.get("targets", "").strip()
        profile_name = request.form.get("profile")
        concurrency = int(request.form.get("concurrency", 10))
        timeout = int(request.form.get("timeout", 5))
        retries = int(request.form.get("retries", 2))

        targets = parse_targets(targets_text)

        if not targets:
            error = "No valid IP addresses found"
        elif not profile_name:
            error = "Please select a credential profile"
        else:
            try:
                profile = run_async(cred_provider.get_profile(profile_name))
                if not profile:
                    error = f"Profile '{profile_name}' not found"
                else:
                    # Create job tracker entry
                    job_tracker = get_job_tracker()
                    job = job_tracker.create_job(
                        job_type="batch",
                        total_targets=len(targets),
                        metadata={"profile": profile_name, "targets_text": targets_text[:100]}
                    )

                    def run_batch_background(job_id: str, targets: list, profile, concurrency: int, timeout: int, retries: int, profile_name: str):
                        """Background task to run batch scan."""
                        job_tracker = get_job_tracker()
                        job_tracker.start_job(job_id)

                        async def do_scan():
                            scanner = DeviceScanner(timeout=timeout, retries=retries)
                            credential = profile.to_snmp_credential()
                            semaphore = asyncio.Semaphore(concurrency)

                            async def scan_one(ip):
                                # Check for cancellation before each scan
                                if job_tracker.is_cancelled(job_id):
                                    return None
                                async with semaphore:
                                    # Check again after acquiring semaphore
                                    if job_tracker.is_cancelled(job_id):
                                        return None
                                    result = await scanner.scan_device(
                                        ip_address=ip,
                                        credential=credential,
                                        scan_type="batch",
                                        credential_profile_name=profile_name,
                                    )
                                    job_tracker.update_progress(job_id, result.success)
                                    return result

                            await asyncio.gather(*[scan_one(ip) for ip in targets])

                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            loop.run_until_complete(do_scan())
                            if not job_tracker.is_cancelled(job_id):
                                job_tracker.complete_job(job_id)
                        except Exception as e:
                            if not job_tracker.is_cancelled(job_id):
                                job_tracker.complete_job(job_id, error=str(e))
                        finally:
                            loop.close()

                    # Run in background thread
                    thread = threading.Thread(
                        target=run_batch_background,
                        args=(job.id, targets, profile, concurrency, timeout, retries, profile_name)
                    )
                    thread.start()

                    flash(f"Batch scan started for {len(targets)} targets. Check progress below.", "info")
                    return redirect(url_for("batch_scan"))

            except Exception as e:
                error = str(e)

    # Get active and recent jobs for display
    job_tracker = get_job_tracker()
    jobs = job_tracker.get_recent_jobs(limit=10)

    return render_template(
        "batch.html", profiles=profiles, error=error, jobs=jobs
    )


# ============== Inventory ==============

@app.route("/inventory")
@login_required
def inventory():
    """Device inventory page."""
    devices = []
    vendors = []
    device_types = []
    error = None

    # Get filter parameters
    vendor_filter = request.args.get("vendor")
    type_filter = request.args.get("type")
    status_filter = request.args.get("status")

    try:
        with get_db_session() as session:
            device_repo = DeviceRepository(session)
            vendors = device_repo.get_vendors()
            device_types = device_repo.get_device_types()

            # Apply filters
            is_active = None
            if status_filter == "active":
                is_active = True
            elif status_filter == "inactive":
                is_active = False

            devices = device_repo.get_all(
                vendor=vendor_filter if vendor_filter else None,
                device_type=type_filter if type_filter else None,
                is_active=is_active,
                limit=10000,  # Increased from 500 to support larger inventories
            )
    except Exception as e:
        error = str(e)

    return render_template(
        "inventory.html",
        devices=devices,
        vendors=vendors,
        device_types=device_types,
        error=error,
        filters={
            "vendor": vendor_filter,
            "type": type_filter,
            "status": status_filter,
        },
    )


@app.route("/inventory/<device_id>")
@login_required
def device_detail(device_id):
    """Device detail page with hardware inventory."""
    device = None
    inventory = None
    scan_history = []
    error = None

    try:
        with get_db_session() as session:
            device_repo = DeviceRepository(session)
            scan_repo = ScanHistoryRepository(session)

            device = device_repo.get_by_id(device_id)
            if not device:
                flash("Device not found", "danger")
                return redirect(url_for("inventory"))

            # Get recent scan history for this device
            scan_history = scan_repo.get_by_device(device_id, limit=10)

            # Check if we have cached inventory in metadata
            if device.metadata_ and "inventory" in device.metadata_:
                inventory = device.metadata_["inventory"]

    except Exception as e:
        error = str(e)

    return render_template(
        "device_detail.html",
        device=device,
        inventory=inventory,
        scan_history=scan_history,
        error=error,
    )


@app.route("/inventory/refresh-all", methods=["POST"])
@login_required
def refresh_all_devices():
    """Refresh all devices by re-scanning them with auto-discover."""
    import threading

    # Get device count first
    with get_db_session() as session:
        device_repo = DeviceRepository(session)
        devices = device_repo.get_all(limit=10000)
        device_ips = [d.ip_address for d in devices]

    if not device_ips:
        flash("No devices to refresh", "warning")
        return redirect(url_for("inventory"))

    # Create job tracker entry
    job_tracker = get_job_tracker()
    job = job_tracker.create_job(
        job_type="refresh_all",
        total_targets=len(device_ips),
        metadata={"description": "Refresh all devices"}
    )

    def run_refresh(job_id: str, device_ips: list):
        """Background task to refresh all devices."""
        job_tracker = get_job_tracker()
        job_tracker.start_job(job_id)

        async def refresh_devices():
            cred_provider = get_credential_provider()
            all_profiles = await cred_provider.get_all_profiles_ordered()

            if not all_profiles:
                raise Exception("No credential profiles configured")

            # Scan all devices with auto-discover
            scanner = DeviceScanner()
            semaphore = asyncio.Semaphore(10)  # Limit concurrency

            async def scan_one(ip):
                # Check for cancellation before each scan
                if job_tracker.is_cancelled(job_id):
                    return
                async with semaphore:
                    # Check again after acquiring semaphore
                    if job_tracker.is_cancelled(job_id):
                        return
                    result = await scanner.scan_device_auto_discover(
                        ip_address=ip,
                        profiles=all_profiles,
                        scan_type="refresh",
                    )
                    job_tracker.update_progress(job_id, result.success)

            await asyncio.gather(*[scan_one(ip) for ip in device_ips])

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(refresh_devices())
            if not job_tracker.is_cancelled(job_id):
                job_tracker.complete_job(job_id)
        except Exception as e:
            if not job_tracker.is_cancelled(job_id):
                job_tracker.complete_job(job_id, error=str(e))
        finally:
            loop.close()

    # Run in background thread
    thread = threading.Thread(target=run_refresh, args=(job.id, device_ips))
    thread.start()

    flash(f"Refresh started for {len(device_ips)} devices. Check Batch Scan page for progress.", "info")
    return redirect(url_for("inventory"))


@app.route("/inventory/<device_id>/rescan", methods=["POST"])
@login_required
def rescan_device(device_id):
    """Rescan a device - tries all profiles and collects full inventory."""
    try:
        # Get device from DB
        with get_db_session() as session:
            device_repo = DeviceRepository(session)
            device = device_repo.get_by_id(device_id)

            if not device:
                flash("Device not found", "danger")
                return redirect(url_for("inventory"))

            ip_address = device.ip_address

        # Get all profiles in priority order
        cred_provider = get_credential_provider()
        all_profiles = run_async(cred_provider.get_all_profiles_ordered())

        if not all_profiles:
            flash("No credential profiles configured", "danger")
            return redirect(url_for("device_detail", device_id=device_id))

        # Rescan with auto-discover (now includes full inventory collection)
        scanner = DeviceScanner()
        scan_result = run_async(
            scanner.scan_device_auto_discover(
                ip_address=ip_address,
                profiles=all_profiles,
                scan_type="rescan",
            )
        )

        if scan_result.success:
            flash(f"Device rescanned successfully using profile '{scan_result.credential_profile_name}'", "success")
        else:
            flash(f"Rescan failed: {scan_result.error}", "warning")

    except Exception as e:
        flash(f"Error rescanning device: {e}", "danger")

    return redirect(url_for("device_detail", device_id=device_id))


# ============== Scan History ==============

@app.route("/history")
@login_required
def scan_history():
    """Scan history page."""
    scans = []
    stats = {"total": 0, "success": 0, "failed": 0, "success_rate": 0}
    error = None

    status_filter = request.args.get("status")
    type_filter = request.args.get("type")

    try:
        with get_db_session() as session:
            scan_repo = ScanHistoryRepository(session)
            stats = scan_repo.get_stats()
            scans = scan_repo.get_recent(
                limit=100,
                status=status_filter if status_filter else None,
                scan_type=type_filter if type_filter else None,
            )
    except Exception as e:
        error = str(e)

    return render_template(
        "history.html",
        scans=scans,
        stats=stats,
        error=error,
        filters={"status": status_filter, "type": type_filter},
    )


# ============== Settings / Credentials ==============

@app.route("/settings")
@login_required
def settings():
    """Settings page - list credentials and scheduler config."""
    cred_provider = get_credential_provider()
    profiles = []
    error = None
    scheduler_status = {}

    try:
        # Get all profiles ordered by priority
        profiles = run_async(cred_provider.get_all_profiles_ordered())
        # Get scheduler status
        scheduler = get_scheduler()
        scheduler_status = scheduler.get_status()
    except Exception as e:
        error = str(e)

    return render_template(
        "settings.html",
        profiles=profiles,
        scheduler_status=scheduler_status,
        error=error,
    )


@app.route("/settings/credential/add", methods=["GET", "POST"])
@login_required
def add_credential():
    """Add new credential profile."""
    error = None

    if request.method == "POST":
        cred_provider = get_credential_provider()
        name = request.form.get("name", "").strip()
        version = request.form.get("version", "v2c")
        description = request.form.get("description", "").strip() or None

        if not name:
            error = "Profile name is required"
        elif run_async(cred_provider.profile_exists(name)):
            error = f"Profile '{name}' already exists"
        else:
            try:
                if version == "v2c":
                    community = request.form.get("community", "")
                    if not community:
                        error = "Community string is required"
                    else:
                        profile = SNMPv2cProfile(
                            name=name, community=community, description=description
                        )
                        run_async(cred_provider.save_profile(profile))
                        flash(f"Profile '{name}' created successfully!", "success")
                        return redirect(url_for("settings"))
                else:
                    username = request.form.get("username", "")
                    if not username:
                        error = "Username is required"
                    else:
                        auth_proto_str = request.form.get("auth_protocol", "")
                        auth_password = request.form.get("auth_password", "") or None
                        priv_proto_str = request.form.get("priv_protocol", "")
                        priv_password = request.form.get("priv_password", "") or None

                        auth_proto = None
                        if auth_proto_str:
                            auth_map = {
                                "MD5": AuthProtocol.MD5,
                                "SHA": AuthProtocol.SHA,
                                "SHA-224": AuthProtocol.SHA224,
                                "SHA-256": AuthProtocol.SHA256,
                            }
                            auth_proto = auth_map.get(auth_proto_str)

                        priv_proto = None
                        if priv_proto_str:
                            priv_map = {
                                "DES": PrivProtocol.DES,
                                "AES-128": PrivProtocol.AES128,
                                "AES-256": PrivProtocol.AES256,
                            }
                            priv_proto = priv_map.get(priv_proto_str)

                        profile = SNMPv3Profile(
                            name=name,
                            username=username,
                            auth_protocol=auth_proto,
                            auth_password=auth_password,
                            priv_protocol=priv_proto,
                            priv_password=priv_password,
                            description=description,
                        )
                        run_async(cred_provider.save_profile(profile))
                        flash(f"Profile '{name}' created successfully!", "success")
                        return redirect(url_for("settings"))
            except Exception as e:
                error = str(e)

    return render_template("credential_form.html", error=error)


@app.route("/settings/credential/delete/<name>", methods=["POST"])
@login_required
def delete_credential(name):
    """Delete a credential profile."""
    cred_provider = get_credential_provider()
    try:
        run_async(cred_provider.delete_profile(name))
        flash(f"Profile '{name}' deleted.", "success")
    except Exception as e:
        flash(f"Error deleting profile: {e}", "danger")
    return redirect(url_for("settings"))


@app.route("/settings/credential/priority/<name>", methods=["POST"])
@login_required
def update_credential_priority(name):
    """Update credential profile priority (move up or down)."""
    cred_provider = get_credential_provider()
    direction = request.form.get("direction", "down")

    try:
        # Get all profiles to find current position
        profiles = run_async(cred_provider.get_all_profiles_ordered())
        profile_names = [p.name for p in profiles]

        if name not in profile_names:
            flash(f"Profile '{name}' not found", "danger")
            return redirect(url_for("settings"))

        current_idx = profile_names.index(name)
        current_profile = profiles[current_idx]
        current_priority = current_profile.priority

        if direction == "up" and current_idx > 0:
            # Swap with profile above
            other_profile = profiles[current_idx - 1]
            other_priority = other_profile.priority
            # If same priority, just decrement current
            if current_priority == other_priority:
                run_async(cred_provider.update_priority(name, current_priority - 1))
            else:
                # Swap priorities
                run_async(cred_provider.update_priority(name, other_priority))
                run_async(cred_provider.update_priority(other_profile.name, current_priority))
        elif direction == "down" and current_idx < len(profiles) - 1:
            # Swap with profile below
            other_profile = profiles[current_idx + 1]
            other_priority = other_profile.priority
            # If same priority, just increment current
            if current_priority == other_priority:
                run_async(cred_provider.update_priority(name, current_priority + 1))
            else:
                # Swap priorities
                run_async(cred_provider.update_priority(name, other_priority))
                run_async(cred_provider.update_priority(other_profile.name, current_priority))

    except Exception as e:
        flash(f"Error updating priority: {e}", "danger")

    return redirect(url_for("settings"))


# ============== Scheduler Settings ==============

@app.route("/settings/scheduler", methods=["POST"])
@login_required
def update_scheduler_settings():
    """Update scheduler settings."""
    from src.config.settings import Settings
    import os

    action = request.form.get("action")
    scheduler = get_scheduler()

    if action == "enable":
        interval = int(request.form.get("interval_hours", 24))
        # Update environment variable (persisted via .env file would be better)
        os.environ["RESCAN_ENABLED"] = "true"
        os.environ["RESCAN_INTERVAL_HOURS"] = str(interval)

        # Clear the settings cache to pick up new values
        from src.config.settings import get_settings
        get_settings.cache_clear()

        # Start or update scheduler
        if not scheduler.is_running():
            scheduler.start()
        else:
            scheduler.update_schedule(interval)

        flash(f"Scheduled rescanning enabled (every {interval} hours)", "success")

    elif action == "disable":
        os.environ["RESCAN_ENABLED"] = "false"
        from src.config.settings import get_settings
        get_settings.cache_clear()

        scheduler.stop()
        flash("Scheduled rescanning disabled", "success")

    elif action == "run_now":
        if scheduler.is_running():
            # Run in background thread to not block request
            import threading
            thread = threading.Thread(target=scheduler.trigger_now)
            thread.start()
            flash("Rescan triggered! Check back in a few minutes for results.", "info")
        else:
            flash("Scheduler is not running. Enable it first.", "warning")

    elif action == "update_interval":
        interval = int(request.form.get("interval_hours", 24))
        os.environ["RESCAN_INTERVAL_HOURS"] = str(interval)
        from src.config.settings import get_settings
        get_settings.cache_clear()

        if scheduler.is_running():
            scheduler.update_schedule(interval)
        flash(f"Rescan interval updated to {interval} hours", "success")

    return redirect(url_for("settings"))


@app.route("/api/scheduler/status")
@api_login_required
def api_scheduler_status():
    """Get scheduler status as JSON."""
    scheduler = get_scheduler()
    return jsonify(scheduler.get_status())


# ============== API Endpoints ==============

@app.route("/api/scan", methods=["POST"])
@api_login_required
def api_scan():
    """API endpoint for single scan."""
    data = request.get_json()
    ip_address = data.get("ip_address")
    profile_name = data.get("profile")

    if not ip_address or not is_valid_ip(ip_address):
        return jsonify({"error": "Invalid IP address"}), 400

    if not profile_name:
        return jsonify({"error": "Profile name required"}), 400

    cred_provider = get_credential_provider()
    profile = run_async(cred_provider.get_profile(profile_name))

    if not profile:
        return jsonify({"error": f"Profile '{profile_name}' not found"}), 404

    try:
        scanner = DeviceScanner()
        result = run_async(
            scanner.scan_device(
                ip_address=ip_address,
                credential=profile.to_snmp_credential(),
                scan_type="api",
                credential_profile_name=profile_name,
            )
        )

        if result.success and result.device_info:
            return jsonify(
                {
                    "success": True,
                    "device": result.device_info.to_dict(),
                    "duration_ms": result.duration_ms,
                }
            )
        else:
            return jsonify(
                {"success": False, "error": result.error, "duration_ms": result.duration_ms}
            )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/devices")
@api_login_required
def api_devices():
    """API endpoint to list devices."""
    try:
        with get_db_session() as session:
            device_repo = DeviceRepository(session)
            devices = device_repo.get_all(limit=10000)
            return jsonify(
                {
                    "devices": [
                        {
                            "ip_address": d.ip_address,
                            "hostname": d.hostname,
                            "vendor": d.vendor,
                            "device_type": d.device_type,
                            "platform": d.platform,
                            "model": d.model,
                            "serial_number": d.serial_number,
                            "software_version": d.software_version,
                            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
                        }
                        for d in devices
                    ]
                }
            )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============== Job Status API ==============

@app.route("/api/jobs")
@api_login_required
def api_get_jobs():
    """Get recent scan jobs."""
    job_tracker = get_job_tracker()
    jobs = job_tracker.get_recent_jobs(limit=10)
    return jsonify({"jobs": [j.to_dict() for j in jobs]})


@app.route("/api/jobs/<job_id>")
@api_login_required
def api_get_job(job_id):
    """Get a specific job status."""
    job_tracker = get_job_tracker()
    job = job_tracker.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job.to_dict())


@app.route("/api/jobs/<job_id>/cancel", methods=["POST"])
@api_login_required
def api_cancel_job(job_id):
    """Cancel a running job."""
    job_tracker = get_job_tracker()
    success = job_tracker.cancel_job(job_id)
    if success:
        return jsonify({"success": True, "message": "Job cancelled"})
    else:
        return jsonify({"success": False, "error": "Job not found or not running"}), 400


@app.route("/inventory/refresh-selected", methods=["POST"])
@api_login_required
def refresh_selected_devices():
    """Refresh selected devices by re-scanning them with auto-discover."""
    import threading

    data = request.get_json()
    device_ids = data.get("device_ids", [])

    if not device_ids:
        return jsonify({"error": "No devices selected"}), 400

    # Get device IPs from database
    with get_db_session() as session:
        device_repo = DeviceRepository(session)
        device_ips = []
        for device_id in device_ids:
            device = device_repo.get_by_id(device_id)
            if device:
                device_ips.append(device.ip_address)

    if not device_ips:
        return jsonify({"error": "No valid devices found"}), 400

    # Create job tracker entry
    job_tracker = get_job_tracker()
    job = job_tracker.create_job(
        job_type="refresh_selected",
        total_targets=len(device_ips),
        metadata={"description": f"Refresh {len(device_ips)} selected devices"}
    )

    def run_refresh(job_id: str, device_ips: list):
        """Background task to refresh selected devices."""
        job_tracker = get_job_tracker()
        job_tracker.start_job(job_id)

        async def refresh_devices():
            cred_provider = get_credential_provider()
            all_profiles = await cred_provider.get_all_profiles_ordered()

            if not all_profiles:
                raise Exception("No credential profiles configured")

            scanner = DeviceScanner()
            semaphore = asyncio.Semaphore(10)

            async def scan_one(ip):
                # Check for cancellation before each scan
                if job_tracker.is_cancelled(job_id):
                    return
                async with semaphore:
                    # Check again after acquiring semaphore
                    if job_tracker.is_cancelled(job_id):
                        return
                    result = await scanner.scan_device_auto_discover(
                        ip_address=ip,
                        profiles=all_profiles,
                        scan_type="refresh",
                    )
                    job_tracker.update_progress(job_id, result.success)

            await asyncio.gather(*[scan_one(ip) for ip in device_ips])

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(refresh_devices())
            if not job_tracker.is_cancelled(job_id):
                job_tracker.complete_job(job_id)
        except Exception as e:
            if not job_tracker.is_cancelled(job_id):
                job_tracker.complete_job(job_id, error=str(e))
        finally:
            loop.close()

    # Run in background thread
    thread = threading.Thread(target=run_refresh, args=(job.id, device_ips))
    thread.start()

    return jsonify({"success": True, "job_id": job.id, "device_count": len(device_ips)})


# ============== Nautobot Integration ==============

def get_nautobot_client():
    """Get a Nautobot client if configured, otherwise return None."""
    settings = get_settings()
    if not settings.nautobot_url or not settings.nautobot_token:
        return None
    from src.integrations.nautobot.client import NautobotClient
    return NautobotClient()


@app.route("/nautobot")
@login_required
def nautobot_dashboard():
    """Nautobot integration dashboard."""
    settings = get_settings()
    configured = bool(settings.nautobot_url and settings.nautobot_token)
    connected = False
    connection_error = None
    stats = {
        "total": 0,
        "pending": 0,
        "no_prefix": 0,
        "no_location": 0,
        "ready": 0,
        "synced": 0,
        "failed": 0,
    }

    if configured:
        try:
            client = get_nautobot_client()
            connected = client.test_connection()
        except Exception as e:
            connection_error = str(e)

        # Get device stats
        try:
            with get_db_session() as session:
                device_repo = DeviceRepository(session)
                sync_repo = NautobotSyncRepository(session)
                stats["total"] = device_repo.count()
                status_counts = sync_repo.count_by_status()
                stats.update(status_counts)
        except Exception as e:
            flash(f"Database error: {e}", "warning")

    return render_template(
        "nautobot/dashboard.html",
        configured=configured,
        connected=connected,
        connection_error=connection_error,
        stats=stats,
        nautobot_url=settings.nautobot_url,
    )


@app.route("/nautobot/test-connection", methods=["POST"])
@api_login_required
def nautobot_test_connection():
    """Test Nautobot API connection."""
    try:
        client = get_nautobot_client()
        if not client:
            return jsonify({"success": False, "error": "Nautobot not configured"})

        if client.test_connection():
            return jsonify({"success": True, "message": "Connection successful"})
        else:
            return jsonify({"success": False, "error": "Connection failed"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/nautobot/status")
@api_login_required
def nautobot_status():
    """Get Nautobot integration status as JSON."""
    settings = get_settings()
    configured = bool(settings.nautobot_url and settings.nautobot_token)

    result = {
        "configured": configured,
        "connected": False,
        "stats": {
            "total": 0,
            "pending": 0,
            "no_prefix": 0,
            "no_location": 0,
            "ready": 0,
            "synced": 0,
            "failed": 0,
        }
    }

    if configured:
        try:
            client = get_nautobot_client()
            result["connected"] = client.test_connection()
        except:
            pass

        try:
            with get_db_session() as session:
                device_repo = DeviceRepository(session)
                sync_repo = NautobotSyncRepository(session)
                result["stats"]["total"] = device_repo.count()
                result["stats"].update(sync_repo.count_by_status())
        except:
            pass

    return jsonify(result)


@app.route("/nautobot/check-location-status", methods=["POST"])
@api_login_required
def nautobot_check_location_status():
    """Check location status for selected devices (runs in background)."""
    import threading

    data = request.get_json()
    device_ids = data.get("device_ids", [])

    if not device_ids:
        return jsonify({"error": "No devices selected"}), 400

    client = get_nautobot_client()
    if not client:
        return jsonify({"error": "Nautobot not configured"}), 400

    # Create job tracker entry
    job_tracker = get_job_tracker()
    job = job_tracker.create_job(
        job_type="nautobot_check_status",
        total_targets=len(device_ids),
        metadata={"description": f"Check location status for {len(device_ids)} devices"}
    )

    def run_status_check(job_id: str, device_ids: list):
        """Background task to check location status."""
        from src.integrations.nautobot.sync import NautobotSyncService

        job_tracker = get_job_tracker()
        job_tracker.start_job(job_id)

        try:
            client = get_nautobot_client()
            sync_service = NautobotSyncService(client)

            with get_db_session() as db_session:
                device_repo = DeviceRepository(db_session)
                sync_repo = NautobotSyncRepository(db_session)

                for device_id in device_ids:
                    if job_tracker.is_cancelled(job_id):
                        break

                    device = device_repo.get_by_id(device_id)
                    if not device:
                        job_tracker.update_progress(job_id, success=False)
                        continue

                    try:
                        status = sync_service.check_device_location_status(device)

                        # Update sync status in DB
                        if not status.has_prefix:
                            sync_repo.mark_no_prefix(device_id)
                        elif not status.has_location:
                            sync_repo.mark_no_location(device_id, status.prefix_id)
                        else:
                            sync_repo.mark_ready(device_id, status.prefix_id)

                        job_tracker.update_progress(job_id, success=True)
                    except Exception as e:
                        sync_repo.mark_failed(device_id, str(e))
                        job_tracker.update_progress(job_id, success=False)

            if not job_tracker.is_cancelled(job_id):
                job_tracker.complete_job(job_id)
        except Exception as e:
            if not job_tracker.is_cancelled(job_id):
                job_tracker.complete_job(job_id, error=str(e))

    # Run in background thread
    thread = threading.Thread(target=run_status_check, args=(job.id, device_ids))
    thread.start()

    return jsonify({"success": True, "job_id": job.id, "device_count": len(device_ids)})


@app.route("/nautobot/ensure-prefixes", methods=["POST"])
@api_login_required
def nautobot_ensure_prefixes():
    """Create missing prefixes/IPs in Nautobot for selected devices (runs in background)."""
    import threading

    data = request.get_json()
    device_ids = data.get("device_ids", [])

    if not device_ids:
        return jsonify({"error": "No devices selected"}), 400

    client = get_nautobot_client()
    if not client:
        return jsonify({"error": "Nautobot not configured"}), 400

    # Create job tracker entry
    job_tracker = get_job_tracker()
    job = job_tracker.create_job(
        job_type="nautobot_ensure_prefixes",
        total_targets=len(device_ids),
        metadata={"description": f"Create prefixes/IPs for {len(device_ids)} devices"}
    )

    def run_ensure_prefixes(job_id: str, device_ids: list):
        """Background task to create prefixes and IPs."""
        from src.integrations.nautobot.sync import NautobotSyncService

        job_tracker = get_job_tracker()
        job_tracker.start_job(job_id)

        try:
            client = get_nautobot_client()
            sync_service = NautobotSyncService(client)

            with get_db_session() as db_session:
                device_repo = DeviceRepository(db_session)
                sync_repo = NautobotSyncRepository(db_session)

                for device_id in device_ids:
                    if job_tracker.is_cancelled(job_id):
                        break

                    device = device_repo.get_by_id(device_id)
                    if not device:
                        job_tracker.update_progress(job_id, success=False)
                        continue

                    try:
                        result = sync_service.ensure_prefix_and_ip(device)
                        if result.success:
                            # Update sync status - now has prefix but need to check location
                            status = sync_service.check_device_location_status(device)
                            if status.has_location:
                                sync_repo.mark_ready(device_id, result.prefix_id)
                            else:
                                sync_repo.mark_no_location(device_id, result.prefix_id)
                            job_tracker.update_progress(job_id, success=True)
                        else:
                            sync_repo.mark_failed(device_id, result.error or "Unknown error")
                            job_tracker.update_progress(job_id, success=False)
                    except Exception as e:
                        sync_repo.mark_failed(device_id, str(e))
                        job_tracker.update_progress(job_id, success=False)

            if not job_tracker.is_cancelled(job_id):
                job_tracker.complete_job(job_id)
        except Exception as e:
            if not job_tracker.is_cancelled(job_id):
                job_tracker.complete_job(job_id, error=str(e))

    # Run in background thread
    thread = threading.Thread(target=run_ensure_prefixes, args=(job.id, device_ids))
    thread.start()

    return jsonify({"success": True, "job_id": job.id, "device_count": len(device_ids)})


@app.route("/nautobot/sync", methods=["POST"])
@api_login_required
def nautobot_sync_devices():
    """Sync selected devices to Nautobot (runs in background)."""
    import threading

    data = request.get_json()
    device_ids = data.get("device_ids", [])

    if not device_ids:
        return jsonify({"error": "No devices selected"}), 400

    client = get_nautobot_client()
    if not client:
        return jsonify({"error": "Nautobot not configured"}), 400

    # Create job tracker entry
    job_tracker = get_job_tracker()
    job = job_tracker.create_job(
        job_type="nautobot_sync",
        total_targets=len(device_ids),
        metadata={"description": f"Sync {len(device_ids)} devices to Nautobot"}
    )

    def run_sync(job_id: str, device_ids: list):
        """Background task to sync devices."""
        from src.integrations.nautobot.sync import NautobotSyncService

        job_tracker = get_job_tracker()
        job_tracker.start_job(job_id)

        try:
            client = get_nautobot_client()
            sync_service = NautobotSyncService(client)

            with get_db_session() as db_session:
                device_repo = DeviceRepository(db_session)
                sync_repo = NautobotSyncRepository(db_session)

                for device_id in device_ids:
                    if job_tracker.is_cancelled(job_id):
                        break

                    device = device_repo.get_by_id(device_id)
                    if not device:
                        job_tracker.update_progress(job_id, success=False)
                        continue

                    try:
                        result = sync_service.sync_device(device)

                        if result.status == "synced":
                            sync_repo.mark_synced(device_id, result.nautobot_device_id)
                            job_tracker.update_progress(job_id, success=True)
                        elif result.status in ("no_prefix", "no_location"):
                            if result.status == "no_prefix":
                                sync_repo.mark_no_prefix(device_id)
                            else:
                                sync_repo.mark_no_location(device_id)
                            job_tracker.update_progress(job_id, success=False)
                        else:
                            sync_repo.mark_failed(device_id, result.error or "Unknown error")
                            job_tracker.update_progress(job_id, success=False)
                    except Exception as e:
                        sync_repo.mark_failed(device_id, str(e))
                        job_tracker.update_progress(job_id, success=False)

            if not job_tracker.is_cancelled(job_id):
                job_tracker.complete_job(job_id)
        except Exception as e:
            if not job_tracker.is_cancelled(job_id):
                job_tracker.complete_job(job_id, error=str(e))

    # Run in background thread
    thread = threading.Thread(target=run_sync, args=(job.id, device_ids))
    thread.start()

    return jsonify({"success": True, "job_id": job.id, "device_count": len(device_ids)})


@app.route("/nautobot/sync-all", methods=["POST"])
@login_required
def nautobot_sync_all_ready():
    """Sync all devices that are ready (have location) to Nautobot."""
    import threading

    client = get_nautobot_client()
    if not client:
        flash("Nautobot not configured", "danger")
        return redirect(url_for("nautobot_dashboard"))

    # Get count of ready devices
    ready_count = 0
    try:
        with get_db_session() as session:
            sync_repo = NautobotSyncRepository(session)
            devices = sync_repo.get_devices_by_status("ready", limit=10000)
            ready_count = len(devices)
    except Exception as e:
        flash(f"Database error: {e}", "danger")
        return redirect(url_for("nautobot_dashboard"))

    if ready_count == 0:
        flash("No devices are ready to sync. Make sure prefixes have locations assigned in Nautobot.", "warning")
        return redirect(url_for("nautobot_dashboard"))

    # Create job tracker entry
    job_tracker = get_job_tracker()
    job = job_tracker.create_job(
        job_type="nautobot_sync",
        total_targets=ready_count,
        metadata={"description": "Sync ready devices to Nautobot"}
    )

    def run_sync(job_id: str):
        """Background task to sync devices."""
        from src.integrations.nautobot.sync import NautobotSyncService

        job_tracker = get_job_tracker()
        job_tracker.start_job(job_id)

        try:
            client = get_nautobot_client()
            sync_service = NautobotSyncService(client)

            with get_db_session() as session:
                sync_repo = NautobotSyncRepository(session)
                device_repo = DeviceRepository(session)
                devices = sync_repo.get_devices_by_status("ready", limit=10000)

                for device in devices:
                    if job_tracker.is_cancelled(job_id):
                        break

                    try:
                        result = sync_service.sync_device(device)
                        if result.status == "synced":
                            sync_repo.mark_synced(str(device.id), result.nautobot_device_id)
                            job_tracker.update_progress(job_id, success=True)
                        else:
                            if result.error:
                                sync_repo.mark_failed(str(device.id), result.error)
                            job_tracker.update_progress(job_id, success=False)
                    except Exception as e:
                        sync_repo.mark_failed(str(device.id), str(e))
                        job_tracker.update_progress(job_id, success=False)

            if not job_tracker.is_cancelled(job_id):
                job_tracker.complete_job(job_id)
        except Exception as e:
            if not job_tracker.is_cancelled(job_id):
                job_tracker.complete_job(job_id, error=str(e))

    # Run in background thread
    thread = threading.Thread(target=run_sync, args=(job.id,))
    thread.start()

    flash(f"Nautobot sync started for {ready_count} devices. Check Batch Scan page for progress.", "info")
    return redirect(url_for("nautobot_dashboard"))


@app.route("/nautobot/refresh-status", methods=["POST"])
@login_required
def nautobot_refresh_status():
    """Refresh location status for all devices from Nautobot."""
    import threading

    client = get_nautobot_client()
    if not client:
        flash("Nautobot not configured", "danger")
        return redirect(url_for("nautobot_dashboard"))

    # Get count of devices
    device_count = 0
    try:
        with get_db_session() as session:
            device_repo = DeviceRepository(session)
            device_count = device_repo.count()
    except Exception as e:
        flash(f"Database error: {e}", "danger")
        return redirect(url_for("nautobot_dashboard"))

    if device_count == 0:
        flash("No devices in inventory", "warning")
        return redirect(url_for("nautobot_dashboard"))

    # Create job tracker entry
    job_tracker = get_job_tracker()
    job = job_tracker.create_job(
        job_type="nautobot_status_check",
        total_targets=device_count,
        metadata={"description": "Check Nautobot location status for all devices"}
    )

    def run_status_check(job_id: str):
        """Background task to check location status."""
        from src.integrations.nautobot.sync import NautobotSyncService

        job_tracker = get_job_tracker()
        job_tracker.start_job(job_id)

        try:
            client = get_nautobot_client()
            sync_service = NautobotSyncService(client)

            with get_db_session() as session:
                device_repo = DeviceRepository(session)
                sync_repo = NautobotSyncRepository(session)
                devices = device_repo.get_all(limit=10000)

                for device in devices:
                    if job_tracker.is_cancelled(job_id):
                        break

                    try:
                        # Skip already synced devices
                        if device.nautobot_sync and device.nautobot_sync.sync_status == "synced":
                            job_tracker.update_progress(job_id, success=True)
                            continue

                        status = sync_service.check_device_location_status(device)

                        if not status.has_prefix:
                            sync_repo.mark_no_prefix(str(device.id))
                        elif not status.has_location:
                            sync_repo.mark_no_location(str(device.id), status.prefix_id)
                        else:
                            sync_repo.mark_ready(str(device.id), status.prefix_id)

                        job_tracker.update_progress(job_id, success=True)
                    except Exception as e:
                        sync_repo.mark_failed(str(device.id), str(e))
                        job_tracker.update_progress(job_id, success=False)

            if not job_tracker.is_cancelled(job_id):
                job_tracker.complete_job(job_id)
        except Exception as e:
            if not job_tracker.is_cancelled(job_id):
                job_tracker.complete_job(job_id, error=str(e))

    # Run in background thread
    thread = threading.Thread(target=run_status_check, args=(job.id,))
    thread.start()

    flash(f"Status check started for {device_count} devices. Check Batch Scan page for progress.", "info")
    return redirect(url_for("nautobot_dashboard"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
