#!/bin/bash

OUTPUT="output.txt"
> "$OUTPUT"

run_test() {
    echo "========================================" >> "$OUTPUT"
    echo "TEST: $1" >> "$OUTPUT"
    echo "CMD: python WebTester.py $2" >> "$OUTPUT"
    echo "----------------------------------------" >> "$OUTPUT"
    python WebTester.py $2 >> "$OUTPUT" 2>&1
    echo "" >> "$OUTPUT"
}

# Success cases
run_test "No scheme (defaults to http)" "www.google.com"
run_test "Explicit HTTP" "http://www.example.com"
run_test "HTTPS (checks HTTP/2)" "https://www.google.com"
run_test "HTTPS with HTTP/2 support" "https://www.cloudflare.com"
run_test "With path" "www.google.com/search"
run_test "With query string" "https://www.google.com/search?q=test"
run_test "HTTP to HTTPS redirect" "http://github.com"
run_test "Multiple redirects" "http://google.com"
run_test "Password protected (401)" "https://httpbin.org/basic-auth/user/pass"
run_test "Site with cookies" "www.amazon.com"

# Error cases
run_test "No argument" ""
run_test "Invalid scheme" "ftp://www.google.com"
run_test "Invalid port" "www.example.com:abc"
run_test "Empty host" "http:///path"
run_test "DNS failure" "thisdomaindoesnotexist12345.com"
run_test "Connection refused" "http://localhost:9999"
run_test "Connection timeout" "http://10.255.255.1"
run_test "SSL error" "https://httpbin.org:80"

echo "Done. Results in $OUTPUT"
