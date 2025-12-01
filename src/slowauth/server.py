"""DNS server implementation for SlowAuth."""

import json
import os
import socket
import sys
import threading
import time
from datetime import datetime
from typing import Optional

from dnslib import DNSRecord, QTYPE, RR, A, AAAA, TXT
from dnslib.server import BaseResolver, DNSServer


class SlowAuthResolver(BaseResolver):
    """DNS resolver for SlowAuth server."""

    def __init__(self, domain: str):
        """Initialize resolver with the domain to serve."""
        self.domain = domain.lower().rstrip(".")
    
    def _get_timestamp(self) -> str:
        """Get formatted timestamp for logging."""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    def _log_json(self, event_type: str, qname: str, qtype: str, client_ip: str, 
                   client_port: str, protocol: str, delay_ms: Optional[int] = None,
                   record_data: Optional[str] = None, error: Optional[str] = None):
        """Log event as JSON."""
        log_data = {
            "timestamp": self._get_timestamp(),
            "event": event_type,
            "domain": qname,
            "record_type": qtype,
            "client_ip": client_ip,
            "client_port": client_port,
            "protocol": protocol
        }
        
        if delay_ms is not None:
            log_data["delay_ms"] = delay_ms
        
        if record_data is not None:
            log_data["record_data"] = record_data
        
        if error is not None:
            log_data["error"] = error
        
        print(json.dumps(log_data))

    def _parse_delay(self, qname: str) -> Optional[int]:
        """Parse delay value from query name.
        
        Args:
            qname: Query name string
            
        Returns:
            Delay in milliseconds if valid, None otherwise
        """
        try:
            # Normalize query name
            query_text = qname.lower().rstrip(".")
            
            # Check if query ends with our domain
            if not query_text.endswith(self.domain):
                return None
            
            # Extract subdomain part
            if query_text == self.domain:
                # Query for root domain, no delay
                return 0
            
            # Remove domain suffix to get subdomain
            subdomain = query_text[: -(len(self.domain) + 1)]
            
            # Parse integer from subdomain
            delay_ms = int(subdomain)
            
            # Ensure non-negative
            if delay_ms < 0:
                return None
                
            return delay_ms
        except (ValueError, AttributeError):
            return None

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        """Resolve DNS query.
        
        Args:
            request: DNS request record
            handler: Request handler (contains peer info)
            
        Returns:
            DNS response record
        """
        # Get query details
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]
        
        # Extract client IP, port, and protocol from handler
        try:
            if hasattr(handler, 'client_address'):
                client_ip = handler.client_address[0]
                client_port = handler.client_address[1] if len(handler.client_address) > 1 else 'unknown'
            elif hasattr(handler, 'request') and hasattr(handler.request, 'getpeername'):
                peer_info = handler.request.getpeername()
                client_ip = peer_info[0]
                client_port = peer_info[1] if len(peer_info) > 1 else 'unknown'
            else:
                client_ip = 'unknown'
                client_port = 'unknown'
            
            # Determine protocol
            if hasattr(handler, 'protocol'):
                protocol = handler.protocol
            elif hasattr(handler, 'request') and hasattr(handler.request, 'type'):
                protocol = 'TCP' if handler.request.type == socket.SOCK_STREAM else 'UDP'
            else:
                protocol = 'unknown'
        except Exception:
            client_ip = 'unknown'
            client_port = 'unknown'
            protocol = 'unknown'
        
        
        # Parse delay from query name
        delay_ms = self._parse_delay(qname)
        
        # Create response
        reply = request.reply()
        # Clear AD (Authenticated Data) flag - we don't implement DNSSEC
        reply.header.ad = False
        # Clear RA (Recursion Available) flag - recursion is not available
        reply.header.ra = False
        
        if delay_ms is None:
            # Invalid subdomain, return SERVFAIL
            reply.header.rcode = 2  # SERVFAIL
            self._log_json("query_received", qname, qtype, client_ip, str(client_port), 
                          protocol, error="INVALID (SERVFAIL)")
            return reply
        
        # Log query received
        self._log_json("query_received", qname, qtype, client_ip, str(client_port), 
                      protocol, delay_ms=delay_ms)
        
        # Apply delay
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)
        
        # Get current timestamp with microseconds
        timestamp = time.time()
        seconds = int(timestamp)
        microseconds = int((timestamp - seconds) * 1_000_000)
        
        # Handle different record types
        if qtype == 'A':
            # A record: 127.0.0.1
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("127.0.0.1"), ttl=0))
            record_data = "127.0.0.1"
            
        elif qtype == 'AAAA':
            # AAAA record: ::1
            reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA("::1"), ttl=0))
            record_data = "::1"
            
        elif qtype == 'TXT':
            # TXT record: timestamp.microseconds
            txt_value = f"{seconds}.{microseconds}"
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(txt_value), ttl=0))
            record_data = txt_value
            
        else:
            # Unsupported record type, return empty response
            record_data = None
        
        # Log response sent
        if record_data:
            self._log_json("response_sent", qname, qtype, client_ip, str(client_port), 
                          protocol, delay_ms=delay_ms, record_data=record_data)
        else:
            self._log_json("response_sent", qname, qtype, client_ip, str(client_port), 
                          protocol, delay_ms=delay_ms, error="no answer")
        
        return reply


class TCPResolverWrapper(BaseResolver):
    """Wrapper resolver that adds TCP protocol info to handler."""
    
    def __init__(self, base_resolver: SlowAuthResolver):
        """Initialize wrapper with base resolver."""
        self.base_resolver = base_resolver
    
    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        """Resolve with TCP protocol info."""
        # Add protocol info to handler
        if not hasattr(handler, 'protocol'):
            handler.protocol = 'TCP'
        return self.base_resolver.resolve(request, handler)


class SlowAuthServer:
    """SlowAuth DNS server."""

    def __init__(self, domain: str = "example.com", port: int = 55533):
        """Initialize DNS server.
        
        Args:
            domain: Domain name to serve (from SLOWAUTH_DOMAIN env var)
            port: Port to listen on (default 55533)
        """
        self.domain = domain
        self.port = port
        self.resolver = SlowAuthResolver(domain)
        self.tcp_resolver = TCPResolverWrapper(self.resolver)
        self.udp_sock = None
        self.running = True
        
    def _handle_udp(self):
        """Handle UDP DNS requests."""
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_sock.bind(("", self.port))
        
        while self.running:
            try:
                self.udp_sock.settimeout(1.0)  # Allow periodic check of self.running
                data, addr = self.udp_sock.recvfrom(512)
                request = DNSRecord.parse(data)
                # Create handler with client address and protocol info
                handler = type('Handler', (), {
                    'client_address': addr,
                    'protocol': 'UDP'
                })()
                response = self.resolver.resolve(request, handler)
                self.udp_sock.sendto(response.pack(), addr)
            except socket.timeout:
                continue  # Timeout is expected, check self.running
            except Exception as e:
                if self.running:
                    error_log = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        "event": "udp_error",
                        "error": str(e),
                        "protocol": "UDP"
                    }
                    print(json.dumps(error_log), file=sys.stderr)
        
        if self.udp_sock:
            self.udp_sock.close()
    
    def start(self):
        """Start the DNS server."""
        startup_log = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "event": "server_start",
            "domain": self.domain,
            "port": self.port,
            "protocols": ["UDP", "TCP"],
            "message": f"Starting SlowAuth DNS server for domain: {self.domain}",
            "format": "<integer>.<domain> where integer is delay in milliseconds"
        }
        print(json.dumps(startup_log))
        
        # Start UDP server in a thread
        udp_thread = threading.Thread(target=self._handle_udp, daemon=True)
        udp_thread.start()
        
        # Create TCP server (DNSServer handles TCP)
        tcp_server = DNSServer(
            self.tcp_resolver,
            port=self.port,
            address="",
            tcp=True,
            logger=None  # We handle our own logging
        )
        
        # Start TCP server (blocks until interrupted)
        try:
            tcp_server.start()
        except KeyboardInterrupt:
            shutdown_log = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "event": "server_shutdown",
                "message": "Shutting down..."
            }
            print(json.dumps(shutdown_log))
            self.running = False
            tcp_server.stop()
            if self.udp_sock:
                self.udp_sock.close()


def main():
    """Main entry point."""
    # Check for required domain environment variable
    domain: str | None = os.environ.get("SLOWAUTH_DOMAIN")
    if not domain:
        print("ERROR: SLOWAUTH_DOMAIN environment variable is not set", file=sys.stderr)
        sys.exit(1)
    
    # Type narrowing: domain is guaranteed to be str after the check above
    assert domain is not None  # Type guard for type checker
    
    # Check for port environment variable, default to 55533
    port_str = os.environ.get("SLOWAUTH_PORT", "55533")
    try:
        port = int(port_str)
    except ValueError:
        print(f"ERROR: SLOWAUTH_PORT must be a valid integer, got '{port_str}'", file=sys.stderr)
        sys.exit(1)
    
    # Validate port range
    if port < 1 or port > 65535:
        print(f"ERROR: SLOWAUTH_PORT must be between 1 and 65535, got '{port}'", file=sys.stderr)
        sys.exit(1)
    
    # All checks passed, start the server
    server = SlowAuthServer(domain, port=port)
    server.start()


if __name__ == "__main__":
    main()
