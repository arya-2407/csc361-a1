#!/usr/bin/env python3
"""
WebTester - A socket-based web testing tool
CSc 361 Programming Assignment 1
"""

import socket
import ssl
import sys


# ============== URL PARSING ==============

def parse_url(url_string):
    """
    Parse URL into components without using urllib.

    Args:
        url_string: URL string (e.g., "https://www.example.com:8080/path")

    Returns:
        dict with keys: scheme, host, port, path
    """
    url = url_string.strip()

    # Extract scheme
    scheme = "http"  # default
    if "://" in url:
        scheme_part, url = url.split("://", 1)
        scheme = scheme_part.lower()

    # Separate host+port from path
    if "/" in url:
        host_port, path = url.split("/", 1)
        path = "/" + path
    else:
        host_port = url
        path = "/"

    # Extract port from host
    port = 443 if scheme == "https" else 80
    if ":" in host_port:
        host, port_str = host_port.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            print(f"Error: Invalid port number in URL")
            sys.exit(1)
    else:
        host = host_port

    # Validate host
    if not host:
        print("Error: Invalid URL format - no host specified")
        sys.exit(1)

    return {
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path
    }


# ============== SOCKET/CONNECTION ==============

def create_socket(host, port, use_ssl):
    """
    Create a TCP socket connection, optionally wrapped with SSL/TLS.

    Args:
        host: hostname string
        port: port integer
        use_ssl: boolean indicating whether to use SSL

    Returns:
        Connected socket object (raw or SSL-wrapped)
    """
    try:
        # Create raw TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # 10 second timeout

        if use_ssl:
            # Create SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Skip certificate verification

            # Wrap socket with SSL
            sock = context.wrap_socket(sock, server_hostname=host)

        # Connect to server
        sock.connect((host, port))
        return sock

    except socket.timeout:
        print(f"Error: Connection to {host}:{port} timed out")
        sys.exit(1)
    except socket.gaierror:
        print(f"Error: Could not resolve hostname {host}")
        sys.exit(1)
    except ConnectionRefusedError:
        print(f"Error: Connection refused by {host}:{port}")
        sys.exit(1)
    except ssl.SSLError as e:
        print(f"Error: SSL/TLS error - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def check_http2_support(host, port=443):
    """
    Check HTTP/2 support using ALPN protocol negotiation during TLS handshake.

    Args:
        host: hostname string
        port: port for HTTPS connection (default 443)

    Returns:
        Boolean indicating HTTP/2 support
    """
    try:
        # Create SSL context with ALPN protocols
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Set ALPN protocols: prefer h2, fallback to http/1.1
        context.set_alpn_protocols(['h2', 'http/1.1'])

        # Create and connect socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.connect((host, port))

        # Check negotiated protocol
        selected = ssl_sock.selected_alpn_protocol()
        ssl_sock.close()

        return selected == 'h2'

    except Exception:
        # Any error means we can't determine HTTP/2 support
        return False


# ============== HTTP ==============

def build_http_request(host, path):
    """
    Build an HTTP/1.1 GET request.

    Args:
        host: hostname for Host header
        path: request path

    Returns:
        HTTP request string
    """
    request = f"GET {path} HTTP/1.1\r\n"
    request += f"Host: {host}\r\n"
    request += "Connection: close\r\n"
    request += "Accept: */*\r\n"
    request += "\r\n"
    return request


def send_request(sock, request):
    """
    Send HTTP request over socket.

    Args:
        sock: connected socket
        request: HTTP request string
    """
    sock.sendall(request.encode('utf-8'))


def receive_response(sock):
    """
    Receive complete HTTP response from socket.

    Args:
        sock: connected socket

    Returns:
        Response string
    """
    response = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        except socket.timeout:
            break

    # Decode with error handling
    try:
        return response.decode('utf-8')
    except UnicodeDecodeError:
        return response.decode('latin-1')


# ============== RESPONSE PARSING ==============

def parse_response(response):
    """
    Parse HTTP response into status line, headers, and body.

    Args:
        response: raw HTTP response string

    Returns:
        tuple: (status_line, headers_dict, body)
    """
    # Split headers from body
    if "\r\n\r\n" in response:
        header_section, body = response.split("\r\n\r\n", 1)
    else:
        header_section = response
        body = ""

    lines = header_section.split("\r\n")
    status_line = lines[0] if lines else ""

    # Parse headers into dict (handle multiple Set-Cookie)
    headers = {}
    for line in lines[1:]:
        if ": " in line:
            key, value = line.split(": ", 1)
            key_lower = key.lower()
            # Handle multiple headers with same name (like Set-Cookie)
            if key_lower in headers:
                if isinstance(headers[key_lower], list):
                    headers[key_lower].append(value)
                else:
                    headers[key_lower] = [headers[key_lower], value]
            else:
                headers[key_lower] = value

    return status_line, headers, body


def get_status_code(status_line):
    """
    Extract HTTP status code from status line.

    Args:
        status_line: e.g., "HTTP/1.1 200 OK"

    Returns:
        int: status code (e.g., 200)
    """
    parts = status_line.split()
    if len(parts) >= 2:
        try:
            return int(parts[1])
        except ValueError:
            return 0
    return 0


def parse_single_cookie(cookie_line):
    """
    Parse a single Set-Cookie header value.

    Args:
        cookie_line: e.g., "SESSID=abc123; expires=Thu, 01-Jan-2025; domain=.example.com"

    Returns:
        dict with keys: name, expires (optional), domain (optional)
    """
    result = {'name': None, 'expires': None, 'domain': None}

    # Split by semicolon
    parts = cookie_line.split(';')

    # First part is name=value
    if parts:
        name_value = parts[0].strip()
        if '=' in name_value:
            name, _ = name_value.split('=', 1)
            result['name'] = name.strip()
        else:
            result['name'] = name_value.strip()

    # Parse attributes
    for part in parts[1:]:
        part = part.strip()
        if '=' in part:
            attr_name, attr_value = part.split('=', 1)
            attr_name_lower = attr_name.strip().lower()
            attr_value = attr_value.strip()

            if attr_name_lower == 'expires':
                result['expires'] = attr_value
            elif attr_name_lower == 'domain':
                result['domain'] = attr_value

    return result if result['name'] else None


def parse_cookies(headers):
    """
    Extract all cookies from Set-Cookie headers.

    Args:
        headers: dict of headers

    Returns:
        list of cookie dicts with name, expires, domain keys
    """
    cookies = []

    set_cookie = headers.get('set-cookie', [])
    if isinstance(set_cookie, str):
        set_cookie = [set_cookie]

    for cookie_line in set_cookie:
        cookie = parse_single_cookie(cookie_line)
        if cookie:
            cookies.append(cookie)

    return cookies


def is_password_protected(headers, status_code):
    """
    Check if resource requires authentication.

    Args:
        headers: dict of headers
        status_code: HTTP status code

    Returns:
        bool: True if password protected
    """
    # Check for 401 Unauthorized status
    if status_code == 401:
        return True

    # Check for WWW-Authenticate header
    if 'www-authenticate' in headers:
        return True

    return False


def get_redirect_location(headers):
    """
    Extract redirect URL from Location header.

    Args:
        headers: dict of headers

    Returns:
        str or None: redirect URL
    """
    return headers.get('location', None)


def handle_redirect(current_url_parts, location):
    """
    Parse redirect location and return new URL parts.

    Args:
        current_url_parts: dict with current scheme, host, port, path
        location: Location header value

    Returns:
        dict with new scheme, host, port, path
    """
    if location.startswith('http://') or location.startswith('https://'):
        # Absolute URL - parse it completely
        return parse_url(location)
    elif location.startswith('//'):
        # Protocol-relative URL
        return parse_url(current_url_parts['scheme'] + ':' + location)
    elif location.startswith('/'):
        # Absolute path - keep host, change path
        new_parts = current_url_parts.copy()
        new_parts['path'] = location
        return new_parts
    else:
        # Relative path - append to current directory
        current_path = current_url_parts['path']
        if '/' in current_path:
            base = current_path.rsplit('/', 1)[0] + '/'
        else:
            base = '/'
        new_parts = current_url_parts.copy()
        new_parts['path'] = base + location
        return new_parts


# ============== OUTPUT ==============

def format_output(url, http2_support, cookies, password_protected):
    """
    Format the final output according to specification.

    Args:
        url: original URL string
        http2_support: boolean
        cookies: list of cookie dicts
        password_protected: boolean

    Returns:
        formatted output string
    """
    output = []
    output.append(f"website: {url}")
    output.append(f"1. Supports http2: {'yes' if http2_support else 'no'}")
    output.append("2. List of Cookies:")

    for cookie in cookies:
        cookie_str = f"cookie name: {cookie['name']}"
        if cookie.get('expires'):
            cookie_str += f", expires time: {cookie['expires']}"
        if cookie.get('domain'):
            cookie_str += f", domain name: {cookie['domain']}"
        output.append(cookie_str)

    output.append(f"3. Password-protected: {'yes' if password_protected else 'no'}")

    return '\n'.join(output)


# ============== MAIN ==============

def main():
    """Main entry point."""
    # Get URL from command line argument
    if len(sys.argv) < 2:
        print("Usage: python WebTester.py <url>")
        sys.exit(1)

    original_url = sys.argv[1]

    # Parse the URL
    url_parts = parse_url(original_url)

    # Check HTTP/2 support (always uses HTTPS)
    # For HTTP URLs, check on port 443; for HTTPS, use the URL's port
    if url_parts['scheme'] == 'https':
        http2_port = url_parts['port']
    else:
        http2_port = 443

    http2_support = check_http2_support(url_parts['host'], http2_port)

    # Initialize for redirect loop
    all_cookies = []
    password_protected = False
    max_redirects = 10
    redirect_count = 0
    current_url = url_parts

    # Follow redirects
    while redirect_count < max_redirects:
        # Create socket (SSL if https)
        use_ssl = (current_url['scheme'] == 'https')
        sock = create_socket(current_url['host'], current_url['port'], use_ssl)

        # Build and send request
        request = build_http_request(current_url['host'], current_url['path'])
        send_request(sock, request)

        # Receive and parse response
        response = receive_response(sock)
        sock.close()

        status_line, headers, _ = parse_response(response)
        status_code = get_status_code(status_line)

        # Collect cookies from this response
        cookies = parse_cookies(headers)
        all_cookies.extend(cookies)

        # Check password protection
        if is_password_protected(headers, status_code):
            password_protected = True

        # Handle redirects (301, 302, 303, 307, 308)
        if status_code in [301, 302, 303, 307, 308]:
            location = get_redirect_location(headers)
            if location:
                current_url = handle_redirect(current_url, location)
                redirect_count += 1
                continue

        # No redirect, exit loop
        break

    # Check if we hit max redirects
    if redirect_count >= max_redirects:
        print("Error: Too many redirects")
        sys.exit(1)

    # Format and print output
    output = format_output(original_url, http2_support, all_cookies, password_protected)
    print(output)


if __name__ == "__main__":
    main()
