import ssl
import socket
from sslyze import (
    ServerConnectivityInfo,
    Scanner,
    SSLCertificateStatus,
    TLSVersion,
    CipherSuite,
)
from sslyze.plugins import HeartbleedPlugin, Tlsv1_0Plugin, Tlsv1_1Plugin, RC4CipherSuitesPlugin

# Function to check SSL/TLS version support and weak ciphers
def check_ssl_vulnerabilities(host, port=443):
    print(f"Checking SSL/TLS vulnerabilities for {host}:{port}")
    
    # Connect to the server to get basic SSL context
    context = ssl.create_default_context()
    try:
        connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
        connection.connect((host, port))
        print(f"SSL connection established to {host}:{port}")
        connection.close()
    except Exception as e:
        print(f"Error establishing SSL connection: {e}")
        return
    
    # Use SSlyze to perform a more in-depth SSL scan
    scanner = Scanner()
    scanner.queue_scan(host, port)

    # Check for Heartbleed vulnerability
    heartbleed_plugin = HeartbleedPlugin()
    scanner.queue_plugin(heartbleed_plugin)
    
    # Check for support of TLS 1.0 and TLS 1.1
    tls_10_plugin = Tlsv1_0Plugin()
    tls_11_plugin = Tlsv1_1Plugin()
    scanner.queue_plugin(tls_10_plugin)
    scanner.queue_plugin(tls_11_plugin)

    # Check for weak RC4 cipher suites
    rc4_plugin = RC4CipherSuitesPlugin()
    scanner.queue_plugin(rc4_plugin)
    
    # Run the scan
    results = scanner.get_results()
    
    for result in results:
        print(f"--- Results for {host} ---")
        print(f"Protocols supported: {result.supported_tls_versions}")
        print(f"Weak ciphers: {result.weak_ciphers}")
        
        # Check for Heartbleed
        heartbleed_vuln = heartbleed_plugin.is_vulnerable_to_heartbleed(result)
        if heartbleed_vuln:
            print("Vulnerable to Heartbleed!")
        
        # TLS 1.0 or TLS 1.1 support
        if TLSVersion.TLSv1_0 in result.supported_tls_versions:
            print("Supports TLS 1.0 (vulnerable to certain attacks, avoid using it).")
        if TLSVersion.TLSv1_1 in result.supported_tls_versions:
            print("Supports TLS 1.1 (vulnerable to certain attacks, avoid using it).")
        
        # Weak ciphers like RC4
        if any(c for c in result.weak_ciphers if CipherSuite.RC4 in c):
            print("Supports weak RC4 cipher suites. This is insecure.")

def main():
    target_host = "example.com"  # Replace with your target
    port = 443  # Default SSL port
    check_ssl_vulnerabilities(target_host, port)

if __name__ == "__main__":
    main()
