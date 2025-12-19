# JIT Inventory

A Python-based network device inventory tool using SNMP to collect hostname, serial number, software version, and hardware inventory from multi-vendor network devices.

## Features

- **Device Auto-Detection**: Automatically identifies device vendor and type via SNMP sysObjectID fingerprinting
- **Multi-Vendor Support**: Supports Cisco (IOS, IOS-XE, NX-OS, ASA) and Arista (EOS), with more vendors coming
- **SNMP v2c & v3**: Full support for SNMPv2c community strings and SNMPv3 with auth/privacy
- **Credential Auto-Discovery**: Define multiple SNMP profiles with priority ordering - automatically finds working credentials
- **Single & Batch Scanning**: Scan individual IPs or entire CIDR ranges
- **Hardware Inventory**: Collect detailed hardware info via Entity MIB (modules, power supplies, fans, stack members)
- **License Tracking**: Collect license information from Cisco devices via CISCO-LICENSE-MGMT-MIB
- **Scheduled Rescanning**: Automatically rescan devices on a configurable schedule
- **Historical Tracking**: All scans stored in PostgreSQL with full history
- **Secure Credentials**: Encrypted local storage for development, AWS Secrets Manager for production
- **Web UI**: Flask-based interface running in Docker

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.11+ (for local development)

### Running with Docker

```bash
# Clone and navigate to the project
cd jit_inventory

# Start the application
docker-compose up --build

# Access the UI at http://localhost:8081
```

### Local Development

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e .

# Start PostgreSQL (or use Docker)
docker-compose up db

# Run Flask
python -m src.app.flask_app
```

## Configuration

Copy `.env.example` to `.env` and adjust settings:

```bash
cp .env.example .env
```

Key settings:
- `DATABASE_URL`: PostgreSQL connection string
- `CREDENTIAL_BACKEND`: `local` (default) or `aws`
- `SNMP_TIMEOUT`: Default timeout in seconds (default: 5)
- `SNMP_RETRIES`: Number of retries (default: 2)
- `RESCAN_ENABLED`: Enable scheduled rescanning (default: false)
- `RESCAN_INTERVAL_HOURS`: Hours between rescans (default: 24)

## Usage

1. **Add Credentials**: Go to Settings page and create SNMP credential profiles
2. **Single Scan**: Enter an IP address to scan a single device (use "Try All Profiles" for auto-discovery)
3. **Batch Scan**: Enter multiple IPs or CIDR ranges to scan in bulk
4. **View Inventory**: See all discovered devices in the Inventory page
5. **Device Details**: Click a device to see full details and collect hardware inventory
6. **Scheduled Rescanning**: Enable in Settings to automatically rescan all devices
7. **History**: Review all scan attempts in Scan History

## Supported Vendors

| Vendor | Status | Platforms |
|--------|--------|-----------|
| Cisco | ✅ Supported | IOS, IOS-XE, NX-OS, ASA |
| Arista | ✅ Supported | EOS |
| Juniper | 🔜 Planned | JunOS |
| F5 | 🔜 Planned | BIG-IP |
| Fortinet | 🔜 Planned | FortiOS |
| Palo Alto | 🔜 Planned | PAN-OS |
| Aruba | 🔜 Planned | AOS-CX, AOS-S |
| Infoblox | 🔜 Planned | NIOS |
| Checkpoint | 🔜 Planned | Gaia |

## Project Structure

```
jit_inventory/
├── src/
│   ├── app/           # Flask UI
│   ├── core/          # Business logic
│   ├── snmp/          # SNMP client
│   ├── vendors/       # Vendor handlers
│   ├── db/            # Database layer
│   ├── credentials/   # Credential management
│   ├── scheduler/     # Scheduled rescanning
│   └── config/        # Configuration
├── data/credentials/  # Local credential storage
├── docker-compose.yml
└── Dockerfile
```

## Adding New Vendors

To add support for a new vendor:

1. Create a new directory under `src/vendors/` (e.g., `src/vendors/arista/`)
2. Implement a handler class extending `VendorHandler` from `src/vendors/base.py`
3. Register the handler in `src/vendors/registry.py`

See `src/vendors/cisco/collector.py` for a reference implementation.

## License

MIT
