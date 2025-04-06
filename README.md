Enhanced Features:

Advanced Detection Techniques:

Regular expression pattern matching for positive identification
Content comparison to detect anomalies
Random marker generation for accurate RFI detection


Extensive Bypass Techniques:

Path traversal with multiple encodings
PHP filter wrappers for LFI
Null byte injection (for PHP < 5.3.4)
Double encoding and URL encoding
Path truncation techniques
Various protocol wrappers


Parameter Scanning:

Automatically detects and tests all parameters in URLs
Smart parameter manipulation


Multiple Request Methods:

Support for both GET and POST requests
Custom headers and cookies support
Proxy support for scanning through web proxies


Better Performance:

Multi-threaded scanning with configurable thread count
Request delay options to avoid detection
Timeout configuration


Improved Error Handling:

Better exception handling
Verbose output options
Comprehensive feedback during scanning


Extended Payload Support:

Comprehensive built-in payload lists
Auto-generation of custom payloads based on bypass techniques
Support for different encoding methods


Additional Security Features:

Random User-Agent rotation to avoid detection
SSL certificate verification options
Follow/don't follow redirects option



Usage Examples:
# Basic LFI scan
python3 lfi_rfi_scanner.py -u "http://example.com/page.php?file=" --lfi

# Basic RFI scan
python3 lfi_rfi_scanner.py -u "http://example.com/page.php?file=" --rfi

# Generate comprehensive payloads
python3 lfi_rfi_scanner.py -u "http://example.com/page.php?file=" --generate-payloads

# Advanced scan with all bypass techniques
python3 lfi_rfi_scanner.py -u "http://example.com/page.php?file=" --auto --encode double --null-byte --filter-bypass

# Using POST method with custom headers and cookies
python3 lfi_rfi_scanner.py -u "http://example.com/page.php" -m POST -d "file=index" -H "X-Forwarded-For: 127.0.0.1" -c "session=test" --lfi
