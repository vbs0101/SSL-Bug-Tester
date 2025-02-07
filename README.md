# SSL-Bug-Tester
This script is designed to test various SSL/TLS vulnerabilities of a remote server. It performs several checks to identify potential issues with SSL/TLS configurations, including:

SSL/TLS version support (e.g., checks if outdated protocols like SSLv2, SSLv3, or TLS 1.0 are enabled).
Weak cipher suites (e.g., checks if the server supports weak ciphers like RC4).
Heartbleed vulnerability (checks if the server is vulnerable to the Heartbleed bug).
TLS 1.0 and 1.1 support (checks for older, insecure TLS versions).
The script leverages the sslyze Python package, which is a powerful SSL scanner that automates the process of identifying common SSL vulnerabilities.

Features
Checks for SSL/TLS version vulnerabilities (SSLv2, SSLv3, TLSv1.0, TLSv1.1).
Identifies weak cipher suites, including RC4.
Detects if the server is vulnerable to the Heartbleed bug.
Reports the results in a user-friendly format.
Requirements
To use the script, you need to have Python 3.6+ installed along with the following dependencies:

sslyze – A library for scanning SSL/TLS configurations.
requests – A library for HTTP requests (if you want to extend the script to include general HTTP checks).
Install Dependencies
You can install the required dependencies using pip:

bash
Copy
pip install sslyze requests
Usage
Clone the repository or download the Python script to your machine.

Modify the target_host variable in the script to the domain or IP address of the server you want to test. By default, the script is configured to scan example.com.

python
Copy
target_host = "example.com"  # Replace with your target domain
Run the script:
bash
Copy
python ssl_vuln_test.py
The script will connect to the target server and perform various SSL/TLS checks. It will output the results directly to your terminal.

Example Output
pgsql
Copy
Checking SSL/TLS vulnerabilities for example.com:443
SSL connection established to example.com:443
--- Results for example.com ---
Protocols supported: [TLSv1_2, TLSv1_3]
Weak ciphers: ['RC4-MD5', 'DES-CBC3-SHA']
Supports TLS 1.0 (vulnerable to certain attacks, avoid using it).
Supports TLS 1.1 (vulnerable to certain attacks, avoid using it).
Supports weak RC4 cipher suites. This is insecure.
Vulnerable to Heartbleed!
Script Breakdown
SSL/TLS Connection: The script attempts to establish an SSL connection to the target host on port 443 using Python's ssl module.
Scanning: The script uses the sslyze library to scan the server for various vulnerabilities, such as outdated SSL/TLS versions, weak ciphers, and Heartbleed.
Output: The results of the scan are printed to the terminal, detailing supported SSL/TLS versions, weak ciphers, and any vulnerabilities detected.
Vulnerability Checks Performed
SSL/TLS Versions: The script checks for insecure versions of SSL/TLS such as SSLv2, SSLv3, TLS 1.0, and TLS 1.1.
Heartbleed Vulnerability: The script checks if the server is vulnerable to the Heartbleed bug, which allowed attackers to leak sensitive information from the server’s memory.
Weak Cipher Suites: The script identifies weak cipher suites like RC4, which are considered insecure and should be avoided.
Deprecated TLS Versions: The script flags servers still using deprecated TLS versions (e.g., TLS 1.0 and TLS 1.1), which are vulnerable to certain attacks.
Troubleshooting
SSL Connection Issues: If the script fails to establish a connection, ensure the target server is running and accessible on port 443.
Permission Issues: If scanning is blocked or restricted by the target server, it may result in a timeout or no results. Some servers block automated scanning attempts.
Missing Dependencies: Ensure that sslyze and requests are installed correctly. You can reinstall them using pip if needed.
Limitations
This script performs basic SSL/TLS vulnerability checks. It does not cover all possible SSL-related vulnerabilities (such as SSL/TLS configuration flaws beyond version and cipher suite selection).
For in-depth security auditing, consider using more specialized tools such as Qualys SSL Labs' SSL Test or OpenSSL for a manual inspection of the SSL/TLS configuration.
Ethical Considerations
Authorization: Always ensure that you have explicit permission to test the SSL/TLS configurations of the target server. Unauthorized scanning can be illegal and considered malicious activity.
Responsible Disclosure: If you identify any vulnerabilities, ensure that you responsibly disclose them to the owner of the affected system.
