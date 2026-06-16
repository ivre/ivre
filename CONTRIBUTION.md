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