# SlowAuth DNS Server

An authoritative DNS server that serves a configurable domain with response delays based on subdomain integer values.

## Features

- Serves A records (127.0.0.1), AAAA records (::1), and TXT records (Unix timestamp with microseconds)
- Configurable response delays based on subdomain integer values (in milliseconds)
- Supports both UDP and TCP protocols
- Comprehensive logging to STDOUT
- Multi-stage Docker build for optimized image size

## Requirements

- Python 3.13+
- uv (Python package manager)
- dnslib

## Installation

### Using uv

```bash
uv sync
```

### Using Docker

```bash
docker build -t slowauth .
```

## Usage

### Environment Variables

- `SLOWAUTH_DOMAIN`: The domain name to serve (required)
- `SLOWAUTH_PORT`: Port to listen on (default: 55533)

### Running Locally

```bash
export SLOWAUTH_DOMAIN=example.com
python -m slowauth.server
```

Or using uv:

```bash
export SLOWAUTH_DOMAIN=example.com
uv run slowauth
```

### Running with Docker

```bash
docker run -p 55533:55533/udp -p 55533:55533/tcp -e SLOWAUTH_DOMAIN=example.com slowauth
```

Or with a custom port:

```bash
docker run -p 5353:5353/udp -p 5353:5353/tcp -e SLOWAUTH_DOMAIN=example.com -e SLOWAUTH_PORT=5353 slowauth
```

## Query Format

Queries should be made to `<integer>.<SLOWAUTH_DOMAIN>`, where `integer` is the number of milliseconds to delay the response.

### Examples

- `100.example.com` - Delays response by 100 milliseconds
- `500.example.com` - Delays response by 500 milliseconds
- `0.example.com` - No delay (immediate response)

## Response Types

### A Records
Returns `127.0.0.1` for A record queries.

```bash
dig @localhost -p 55533 100.example.com A
```

### AAAA Records
Returns `::1` for AAAA record queries.

```bash
dig @localhost -p 55533 100.example.com AAAA
```

### TXT Records
Returns Unix timestamp with microseconds in the format `<seconds>.<microseconds>`.

```bash
dig @localhost -p 55533 100.example.com TXT
```

## Logging

The server logs all queries and responses to STDOUT in JSON format:

```json
{"timestamp": "2025-12-01 18:22:53.187", "event": "query_received", "domain": "300.example.com", "record_type": "TXT", "client_ip": "172.17.0.1", "client_port": "53115", "protocol": "UDP", "delay_ms": 300}
{"timestamp": "2025-12-01 18:22:53.496", "event": "response_sent", "domain": "300.example.com", "record_type": "TXT", "client_ip": "172.17.0.1", "client_port": "53115", "protocol": "UDP", "delay_ms": 300, "record_data": "1764613373.487920"}
```

## Error Handling

- Invalid subdomains (non-integer values) return SERVFAIL
- Queries for domains not matching `SLOWAUTH_DOMAIN` return SERVFAIL
- Missing `SLOWAUTH_DOMAIN` environment variable causes the server to exit with an error

## Port

The server listens on port **55533** by default (both UDP and TCP), configurable via the `SLOWAUTH_PORT` environment variable. 

## Development

```bash
# Install dependencies
uv sync

# Run server
export SLOWAUTH_DOMAIN=example.com
uv run slowauth
```

