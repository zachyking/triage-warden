# Installation

## Building from Source

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install uv (Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/your-org/triage-warden.git
cd triage-warden

# Build Rust components
cargo build --release

# Install Python dependencies
cd python
uv sync
```

### Verify Installation

```bash
# Check the CLI
./target/release/tw-cli --version

# Run tests
cargo test
cd python && uv run pytest
```

## Docker

```bash
# Build the image
docker build -t triage-warden .

# Run with default settings
docker run -p 8080:8080 triage-warden

# Run with custom configuration
docker run -p 8080:8080 \
  -e TW_DATABASE_URL=postgres://user:pass@host/db \
  -e TW_VIRUSTOTAL_API_KEY=your-key \
  triage-warden
```

## Pre-built Binaries

Download the latest release from the [releases page](https://github.com/your-org/triage-warden/releases).

Available platforms:
- Linux x86_64 (glibc)
- Linux x86_64 (musl)
- macOS x86_64
- macOS aarch64 (Apple Silicon)

```bash
# Example for macOS
curl -LO https://github.com/your-org/triage-warden/releases/latest/download/triage-warden-macos-aarch64.tar.gz
tar xzf triage-warden-macos-aarch64.tar.gz
./tw-cli --version
```

## Database Setup

### SQLite (Default)

SQLite is used by default. The database file is created automatically:

```bash
# Default location
TW_DATABASE_URL=sqlite://./triage_warden.db

# Custom location
TW_DATABASE_URL=sqlite:///var/lib/triage-warden/data.db
```

### PostgreSQL

For production deployments:

```bash
# Create database
createdb triage_warden

# Set connection string
export TW_DATABASE_URL=postgres://user:password@localhost/triage_warden

# Run migrations
tw-cli db migrate
```

## Next Steps

- [Quick Start](./quickstart.md) - Create your first incident
- [Configuration](./configuration.md) - Configure the system
