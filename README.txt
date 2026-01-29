The WebTester tool follows all the specfications laid out in the programming spec.

Usage:
1. Ensure you are in the project root. if not: `cd <into project root>` 
2. Location check: at this point if you run `cat WebTester.py`, you should be able to see the contents of the tool.
3. to test the program, run `python3 WebTester.py <url>`
4. output will be to stdout (terminal)

Output:
The program outputs in this format:
"""
input: <input URI>
1. Supports http2: <yes/no>
2. List of Cookies:
cookie name: <name of cookie>
...
3. Password-protected: <yes/no>

<Server Responses>
"""

This program also has sophisticated error handling. These are the error types being handled:

  TYPE                    MESSAGE                                                                       
  ----                    -------                                                                       
  Invalid port            Error: Invalid port number in URL                                             
  Empty host              Error: Invalid URL format - no host specified                                 
  Connection timeout      Error: Connection to {host}:{port} timed out                                  
  DNS failure             Error: Could not resolve hostname {host}                                      
  Connection refused      Error: Connection refused by {host}:{port}                                    
  SSL/TLS error           Error: SSL/TLS error - {e}                                                    
  Generic socket error    Error: {e}                                                                    
  Redirect loop           Error: Too many redirects                                                     
  Missing argument        Usage: python WebTester.py <url>   

Programming process:
    1. URL parsing
    2. Socket Connection
    3. Building HTTP request
    4. Recieve and parse HTTP response
    5. Format output

    * Step 2,3,4 wrapped in a while loop to handle redirects.

