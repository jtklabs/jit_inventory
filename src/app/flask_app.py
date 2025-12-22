"""
Flask application for Network Device Inventory.
"""
import asyncio
import logging
import os
from functools import wraps

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash

# Configure logging
log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

from src.config.settings import get_settings
from src.core.ip_utils import is_valid_ip, parse_targets, estimate_target_count
from src.core.scanner import DeviceScanner
from src.credentials import get_credential_provider
from src.credentials.models import SNMPv2cProfile, SNMPv3Profile
from src.db.connection import get_db_session
from src.db.repositories.device import DeviceRepository
from src.db.repositories.scan import ScanHistoryRepository
from src.scheduler import get_scheduler
from src.snmp.client import AuthProtocol, PrivProtocol

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-in-production"

# Initialize scheduler on app startup
_scheduler_initialized = False


def init_scheduler():
    """Initialize the scheduler (called once on first request)."""
    global _scheduler_initialized
    if not _scheduler_initialized:
        scheduler = get_scheduler()
        scheduler.start()
        _scheduler_initialized = True


@app.before_request
def before_request():
    """Run before each request."""
    init_scheduler()


def run_async(coro):
    """Run async coroutine in sync context."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ============== Dashboard ==============

@app.route("/")
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
def batch_scan():
    """Batch scan page."""
    cred_provider = get_credential_provider()
    profiles = run_async(cred_provider.list_profiles())
    results = []
    error = None
    summary = None

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

                    async def run_batch():
                        scanner = DeviceScanner(timeout=timeout, retries=retries)
                        credential = profile.to_snmp_credential()
                        semaphore = asyncio.Semaphore(concurrency)
                        batch_results = []

                        async def scan_one(ip):
                            async with semaphore:
                                return await scanner.scan_device(
                                    ip_address=ip,
                                    credential=credential,
                                    scan_type="batch",
                                    credential_profile_name=profile_name,
                                )

                        tasks = [scan_one(ip) for ip in targets]
                        batch_results = await asyncio.gather(*tasks)
                        return batch_results

                    results = run_async(run_batch())
                    success_count = sum(1 for r in results if r.success)
                    summary = {
                        "total": len(results),
                        "success": success_count,
                        "failed": len(results) - success_count,
                    }
                    flash(
                        f"Batch scan completed: {success_count}/{len(results)} successful",
                        "success",
                    )
            except Exception as e:
                error = str(e)

    return render_template(
        "batch.html", profiles=profiles, results=results, error=error, summary=summary
    )


# ============== Inventory ==============

@app.route("/inventory")
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
                limit=500,
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
def refresh_all_devices():
    """Refresh all devices by re-scanning them with auto-discover."""
    import threading

    def run_refresh():
        """Background task to refresh all devices."""
        import asyncio

        async def refresh_devices():
            cred_provider = get_credential_provider()
            all_profiles = await cred_provider.get_all_profiles_ordered()

            if not all_profiles:
                return 0, 0, "No credential profiles configured"

            # Get all devices
            with get_db_session() as session:
                device_repo = DeviceRepository(session)
                devices = device_repo.get_all(limit=1000)
                device_ips = [d.ip_address for d in devices]

            if not device_ips:
                return 0, 0, "No devices to refresh"

            # Scan all devices with auto-discover
            scanner = DeviceScanner()
            semaphore = asyncio.Semaphore(10)  # Limit concurrency
            success_count = 0
            fail_count = 0

            async def scan_one(ip):
                nonlocal success_count, fail_count
                async with semaphore:
                    result = await scanner.scan_device_auto_discover(
                        ip_address=ip,
                        profiles=all_profiles,
                        scan_type="refresh",
                    )
                    if result.success:
                        success_count += 1
                    else:
                        fail_count += 1

            await asyncio.gather(*[scan_one(ip) for ip in device_ips])
            return success_count, fail_count, None

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(refresh_devices())
        finally:
            loop.close()

    # Run in background thread
    thread = threading.Thread(target=run_refresh)
    thread.start()

    flash("Refresh started! All devices will be rescanned in the background.", "info")
    return redirect(url_for("inventory"))


@app.route("/inventory/<device_id>/rescan", methods=["POST"])
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
def api_scheduler_status():
    """Get scheduler status as JSON."""
    scheduler = get_scheduler()
    return jsonify(scheduler.get_status())


# ============== API Endpoints ==============

@app.route("/api/scan", methods=["POST"])
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
def api_devices():
    """API endpoint to list devices."""
    try:
        with get_db_session() as session:
            device_repo = DeviceRepository(session)
            devices = device_repo.get_all(limit=1000)
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


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
