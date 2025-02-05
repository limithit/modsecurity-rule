## Generate some common rules such as preventing burst force cracking of ledger secrets, log4j2 and CVE vulnerabilities in recent years
ModSecurity is an open source Web Application Firewall (WAF) for detecting and preventing attacks on Web applications. modSecurity can use a set of rules to match and process requests and responses. Each rule has a unique ID that identifies and references the rule1.

There are no strict limits on the range of IDs for ModSecurity rules, but there are some conventions and recommendations. In general, the ID should be a six-digit number from 100000 to 9999992. Different rule sets can use different ID ranges to avoid conflicts. For example, the OWASP ModSecurity Core Rule Set (CRS) uses a range of 900000 to 999999.1 Custom rules can use any unoccupied ID range, but it is recommended to avoid overlap with existing rule sets. One possible approach is to use a range of 100000 to 1999992.

The order in which ModSecurity rules are executed is not determined by the ID, but by the phase (phase) in which the rules are located and the order in which the files are loaded. modSecurity has five phases, request header (1), request body (2), response header (3), response body (4) and log (5). Within each phase, rules are executed in the order in which the files are loaded. If there are multiple files containing rules for the same phase, then the file names are sorted alphabetically and the rules in the file loaded first are executed first.

###  Test on libmodsecurity.so.3.0.8 & ModSecurity-nginx v1.0.3


## Tips
In ModSecurity rules, the phase parameter is optional. If not specified, the default rule will execute in Phase 2 (request processing phase).

However, when handling response content, it is usually necessary to explicitly specify execution in Phase 4 (response processing phase), as this is when the server processes the response body.

If your rule does not correctly specify Phase 4, it may not match the keyword in the response content.
