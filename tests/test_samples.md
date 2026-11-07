# Test Samples

These sample URLs are used to test the Phishing URL Awareness Checker. They are text samples only and are not visited.

| # | Input | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| 1 | `https://www.example.com/login` | Additional keyword check may flag `login` | Risk Score: 6/100; LOW RISK; suspicious keyword `login` | PASS |
| 2 | `http://192.0.2.10/account` | IP address; HTTP | IP address; HTTP; suspicious keyword `account` | PASS |
| 3 | `http://example.com@sample.invalid/login` | `@` symbol; HTTP | `@` symbol; HTTP; suspicious keyword `login` | PASS |
| 4 | `https://a.b.c.d.e.example.invalid/path` | Five or more hostname parts | Five or more hostname parts | PASS |
| 5 | `https://xn--example.invalid/` | Punycode marker | Punycode marker | PASS |

## Safety Note

The checker analyzes URL text only. It does not visit websites or contact external services.

A URL with no warning indicators is not guaranteed to be safe.
