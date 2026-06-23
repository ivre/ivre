# Contribution README

## Issue
[Store more data from Nmap scan results · Issue #655](https://github.com/ivre/ivre/issues/655)

## Steps to Reproduce

### Reproduction Process
1. Fork and clone the IVRE repository and open it in a GitHub Codespace
2. Run `grep -r "tcpsequence" .` from the project root
3. Observe that `ivre/activecli.py` line 439 contains a TODO comment stating data from `tcpsequence` and `ipidsequence` is currently missing
4. Run `grep -r "ipidsequence" .` to confirm — no parsing or storage logic exists for either tag anywhere in the codebase
5. Open `ivre/activecli.py` and navigate to line 439 — the TODO sits inside the host info display function, confirming the data is never read from Nmap XML output

**Expected:** IVRE stores `tcpsequence` and `ipidsequence` values from Nmap XML scan results  
**Actual:** Both fields are silently dropped — only a TODO comment marks the gap

### Reproduction Evidence
Branch: https://github.com/chjohn5577/ivre/tree/fix-issue-ivre

## Implementation Plan
- Locate where IVRE parses Nmap XML input (near `activecli.py` and the XML ingestion pipeline)
- Add logic to extract `tcpsequence` and `ipidsequence` attributes from Nmap XML output
- Update the data schema/model to store these new fields
- Replace the TODO comment in `activecli.py` with actual display logic for those values
- Test using a sample Nmap XML file that contains these tags

UMPIRE Plan
Understand
When IVRE parses Nmap XML scan results, it extracts and stores many fields (OS matches, hostnames, ports, traces, etc.) but completely ignores two XML tags: <tcpsequence> and <ipidsequence>. These tags contain useful fingerprinting data about how a host generates TCP sequence numbers and IP IDs — useful for OS detection and network analysis. The data is silently dropped during parsing. There is a # TODO comment in ivre/activecli.py at line 439 acknowledging this gap.

Match
The existing pattern for osclass and osmatch in ivre/xmlnmap.py around line 2133 is the model to follow:
pythonelif name in ["osclass", "osmatch"] and "os" in self._curhost:
    self._curhost["os"].setdefault(name, []).append(dict(attrs))
The same startElement method already handles os, portused, osfingerprint, and trace the same way — read the tag name, extract attributes, store them on self._curhost. The tcpsequence and ipidsequence tags follow the exact same pattern.

Plan

In ivre/xmlnmap.py, inside the startElement method, add a new elif block after the osfingerprint handler (around line 2137) to capture tcpsequence and ipidsequence:

pythonelif name in ["tcpsequence", "ipidsequence"]:
    self._curhost[name] = dict(attrs)

In ivre/activecli.py, replace the # TODO comment at line 439 with logic that reads and displays those fields from the host object
Optionally update any type hint files (check ivre/types.py) if the host schema is formally defined there


Implement
(Phase III — branch link: https://github.com/chjohn5577/ivre/tree/fix-issue-ivre)

Review

No CONTRIBUTING.md exists in the repo — will follow conventions observed in the codebase (type hints, docstrings, existing code style)
Will run the linting workflow locally: grep confirms the project uses flake8/pylint via .github/workflows/linting.yml
Commit message will follow the pattern seen in the project history: short imperative summary, e.g. Store tcpsequence and ipidsequence from Nmap XML results


Evaluate

Add a sample Nmap XML snippet containing <tcpsequence> and <ipidsequence> tags to the test samples
Run python -m pytest tests/ or python tests/tests_no_backend.py to confirm no regressions
Manually verify by parsing a test XML file and checking that the resulting host object contains tcpsequence and ipidsequence fields
## Phase III — Implementation

### Changes Made
- `ivre/xmlnmap.py` — added `elif` block in `startElement` to parse and store
  `tcpsequence` and `ipidsequence` XML tags from Nmap scan results
- `ivre/activecli.py` — replaced TODO comment with display logic for both fields
- `tests/tests_no_backend.py` — added `NmapSequenceParsingTests` class with 3 tests

### Test Results
- 3 new tests written and passing
- 366 existing tests still passing
- 12 pre-existing failures confirmed unrelated (nmap not installed in Codespace,
  screenshot image handling, CLI utilities)

### Linting
- Black formatting applied and verified clean
- flake8 E501 errors are all pre-existing in unchanged lines per CONTRIBUTING guidelines

### Branch
https://github.com/chjohn5577/ivre/tree/fix-issue-ivre