"""DNS server implementation for SlowAuth."""

import asyncio
import json
import os
import signal
import socket
import sys
import time
from datetime import datetime
from typing import Optional

from dnslib import DNSRecord, QTYPE, RR, A, AAAA, TXT


class SlowAuthResolver:
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

    async def resolve(self, request: DNSRecord, client_ip: str, client_port: str, protocol: str) -> DNSRecord:
        """Resolve DNS query asynchronously.
        
        Args:
            request: DNS request record
            client_ip: Client IP address
            client_port: Client port
            protocol: Protocol ('UDP' or 'TCP')
            
        Returns:
            DNS response record
        """
        # Get query details
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]
        
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
        
        # Apply delay asynchronously
        if delay_ms > 0:
            await asyncio.sleep(delay_ms / 1000.0)
        
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
        self.udp_transport = None
        self.tcp_server = None
        
    async def _handle_udp_request(self, data: bytes, addr: tuple):
        """Handle a single UDP DNS request."""
        try:
            request = DNSRecord.parse(data)
            client_ip, client_port = addr
            response = await self.resolver.resolve(request, client_ip, client_port, "UDP")
            if self.udp_transport:
                self.udp_transport.sendto(response.pack(), addr)
        except Exception as e:
            error_log = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "event": "udp_error",
                "error": str(e),
                "protocol": "UDP",
                "client_ip": addr[0] if addr else "unknown",
                "client_port": addr[1] if addr and len(addr) > 1 else "unknown"
            }
            print(json.dumps(error_log), file=sys.stderr)
    
    def _udp_protocol_factory(self):
        """Create UDP protocol handler."""
        server = self
        
        class UDPProtocol(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple):
                """Handle received UDP datagram."""
                # Create task for concurrent handling
                asyncio.create_task(server._handle_udp_request(data, addr))
        
        return UDPProtocol()
    
    async def _handle_tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a TCP client connection."""
        try:
            addr = writer.get_extra_info('peername')
            client_ip = addr[0] if addr else 'unknown'
            client_port = addr[1] if addr and len(addr) > 1 else 'unknown'
            
            while True:
                # Read length prefix (2 bytes, network byte order)
                length_data = await reader.readexactly(2)
                if len(length_data) < 2:
                    break  # Connection closed
                
                # Get message length
                msg_length = int.from_bytes(length_data, 'big')
                
                # Read DNS message
                data = await reader.readexactly(msg_length)
                
                # Parse and resolve
                request = DNSRecord.parse(data)
                response = await self.resolver.resolve(request, client_ip, str(client_port), "TCP")
                
                # Send response with length prefix
                response_data = response.pack()
                writer.write(len(response_data).to_bytes(2, 'big') + response_data)
                await writer.drain()
        except asyncio.IncompleteReadError:
            # Client closed connection
            pass
        except Exception as e:
            error_log = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "event": "tcp_error",
                "error": str(e),
                "protocol": "TCP",
                "client_ip": client_ip if 'client_ip' in locals() else "unknown",
                "client_port": client_port if 'client_port' in locals() else "unknown"
            }
            print(json.dumps(error_log), file=sys.stderr)
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def start(self):
        """Start the DNS server asynchronously."""
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
        
        # Start UDP server
        loop = asyncio.get_running_loop()
        try:
            self.udp_transport, _ = await loop.create_datagram_endpoint(
                self._udp_protocol_factory,
                local_addr=("0.0.0.0", self.port),
                family=socket.AF_INET
            )
            udp_addr = self.udp_transport.get_extra_info('sockname')
            udp_log = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "event": "udp_server_started",
                "address": f"{udp_addr[0]}:{udp_addr[1]}" if udp_addr else "unknown",
                "protocol": "UDP"
            }
            print(json.dumps(udp_log))
        except Exception as e:
            error_log = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "event": "udp_server_error",
                "error": str(e),
                "protocol": "UDP"
            }
            print(json.dumps(error_log), file=sys.stderr)
            raise
        
        # Start TCP server
        try:
            self.tcp_server = await asyncio.start_server(
                self._handle_tcp_client,
                host="0.0.0.0",
                port=self.port,
                family=socket.AF_INET
            )
            tcp_addrs = [sock.getsockname() for sock in self.tcp_server.sockets]
            tcp_log = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "event": "tcp_server_started",
                "addresses": [f"{addr[0]}:{addr[1]}" for addr in tcp_addrs],
                "protocol": "TCP"
            }
            print(json.dumps(tcp_log))
        except Exception as e:
            error_log = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "event": "tcp_server_error",
                "error": str(e),
                "protocol": "TCP"
            }
            print(json.dumps(error_log), file=sys.stderr)
            raise
        
        # Run TCP server (UDP is already running via the transport)
        # serve_forever() will keep the server running
        await self.tcp_server.serve_forever()
    
    async def stop(self):
        """Stop the DNS server."""
        shutdown_log = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "event": "server_shutdown",
            "message": "Shutting down..."
        }
        print(json.dumps(shutdown_log))
        
        if self.udp_transport:
            self.udp_transport.close()
        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()


async def _main_async():
    """Async main entry point."""
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
    
    # Set up signal handlers for graceful shutdown
    loop = asyncio.get_event_loop()
    shutdown_event = asyncio.Event()
    
    def signal_handler():
        shutdown_event.set()
    
    # Handle SIGINT (Ctrl+C) and SIGTERM (if available on platform)
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, signal_handler)
    except (NotImplementedError, ValueError):
        # Signal handlers not available on this platform (e.g., Windows)
        pass
    
    server_task = None
    try:
        # Start server and wait for shutdown signal
        server_task = asyncio.create_task(server.start())
        await shutdown_event.wait()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
    except KeyboardInterrupt:
        # Fallback for platforms without signal handlers
        if server_task:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
    finally:
        await server.stop()


def main():
    """Main entry point."""
    asyncio.run(_main_async())


if __name__ == "__main__":
    main()
