# XHunter

A powerful, concurrent vulnerability scanner written in Go that tests for XSS (Cross-Site Scripting) and SQLi (SQL Injection) vulnerabilities in web applications.

## Features

- **Multiple Injection Methods**: Supports various injection types (uri, param, finder, clusterbomb)
- **Multi-threading**: Configurable thread count for faster scanning
- **Attack Modes**: 
  - XSS detection using headless Chrome/Selenium
  - Time-based SQL injection detection
- **Flexible Input**:
  - Test single URLs or read from files
  - Use custom payloads or wordlists
  - Pipe URLs from other tools
- **Custom Parameter Testing**: Specify which parameters to test
- **Attack Strategies**: Replace values or append payloads to existing values

## Installation

### Requirements

- Go 1.16 or higher
- ChromeDriver in your PATH (for XSS detection)

### Install using Go

```bash
go install github.com/gilsgil/xhunter@latest
```

## Usage

### Basic Examples

Test a single URL for XSS:
```bash
xhunter -u "http://example.com/page?param=test" -w payloads.txt -m xss
```

Test multiple URLs from a file for SQL injection:
```bash
xhunter -l urls.txt -w sqli-payloads.txt -m sqli
```

### Command Line Options

```
  -u string
        Single URL to test (XSS or SQLi)
  -l string
        Path to file with list of URLs
  -w string
        Path to file with payloads
  -a string
        Attack type: 'postfix' or 'replace' (default "postfix")
  -it string
        Injection type: 'uri', 'param', 'finder', 'clusterbomb' (default "param")
  -m string
        Mode: 'xss' or 'sqli' (default "xss")
  -t int
        Number of threads (default 10)
  -v    Enable verbose logging
  -param string
        Custom parameter(s) for injection (comma-separated)
  -payload string
        Custom payload for injection
```

### Injection Types

- **uri**: Injects payloads directly in the URL path
- **param**: Injects payloads into each parameter individually
- **finder**: Uses an extensive set of common parameters for testing
- **clusterbomb**: Injects the same payload into all parameters simultaneously

### Attack Types

- **postfix**: Appends the payload to the existing parameter value
- **replace**: Replaces the parameter value with the payload

## Advanced Usage

### Custom Parameter Testing

Test specific parameters with a custom payload:
```bash
xhunter -u "http://example.com/page" -param "id,user,token" -payload "<script>alert(1)</script>" -m xss
```

Test multiple URLs with custom parameters from a wordlist:
```bash
xhunter -l urls.txt -param "id,user" -w xss-payloads.txt -it clusterbomb -m xss
```

### Pipeline Usage

Integrate with other tools:
```bash
cat domains.txt | httpx -silent | xhunter -w payloads.txt -m xss
```

## XSS Detection

The tool uses Selenium with headless Chrome to detect XSS vulnerabilities by checking for JavaScript alerts. Make sure ChromeDriver is installed and available in your PATH.

## SQLi Detection

SQL injection detection is time-based, looking for responses that take between 21-25 seconds which may indicate a successful time-based SQL injection.

## Example Payloads

### XSS Payloads Example
```
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
"><script>alert('XSS')</script>
```

### SQLi Payloads Example
```
' OR SLEEP(23)--
" OR SLEEP(23)--
' WAITFOR DELAY '00:00:23'--
```

## Disclaimer

This tool is intended for legal security testing with proper authorization. Do not use it against systems you don't have permission to test.

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
