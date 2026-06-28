# Contribution README

## Issue
[Store more data from Nmap scan results · Issue #655](https://github.com/ivre/ivre/issues/655)

## Pull Request
[Fix issue ivre · Pull Request #1911 · ivre/ivre](https://github.com/ivre/ivre/pull/1911)

## Summary
IVRE was silently dropping `<tcpsequence>` and `<ipidsequence>` data from Nmap XML scan results. A `# TODO` comment in `ivre/activecli.py` at line 439 acknowledged the gap. These fields contain host fingerprinting data useful for OS detection and network analysis. This contribution adds parsing, storage, and display of both fields, along with 3 new unit tests.

### Changes Made
- `ivre/xmlnmap.py` — added `elif` block in `startElement` to parse and store `tcpsequence` and `ipidsequence` XML tags from Nmap scan results
- `ivre/activecli.py` — replaced TODO comment with display logic for both fields
- `tests/tests_no_backend.py` — added `NmapSequenceParsingTests` class with 3 tests

### Key Commits
- `82d689dc` Store tcpsequence and ipidsequence from Nmap XML results
- `4347cb6b` Display tcpsequence and ipidsequence in host output
- `1b36d371` Add tests for tcpsequence and ipidsequence parsing
- `024d7295` Apply Black formatting to tests

## Steps to Reproduce

### Reproduction Process
1. Fork and clone the IVRE repository and open it in a GitHub Codespace
2. Run `grep -r "tcpsequence" .` from the project root
3. Observe that `ivre/activecli.py` line 439 contains a TODO comment stating data from `tcpsequence` and `ipidsequence` is currently missing
4. Run `grep -r "ipidsequence" .` to confirm — no parsing or storage logic exists for either tag anywhere in the codebase
5. Open `ivre/activecli.py` and navigate to line 439 — the TODO sits inside the host info display function, confirming the data is never read from Nmap XML output

**Expected:** IVRE stores `tcpsequence` and `ipidsequence` values from Nmap XML scan results  
**Actual:** Both fields are silently dropped — only a TODO comment marks the gap

## Implementation Plan

- Locate where IVRE parses Nmap XML input (near `activecli.py` and the XML ingestion pipeline)
- Add logic to extract `tcpsequence` and `ipidsequence` attributes from Nmap XML output
- Update the data schema/model to store these new fields
- Replace the TODO comment in `activecli.py` with actual display logic for those values
- Test using a sample Nmap XML file that contains these tags

### UMPIRE Plan

**Understand**  
When IVRE parses Nmap XML scan results, it extracts and stores many fields (OS matches, hostnames, ports, traces, etc.) but completely ignores two XML tags: `<tcpsequence>` and `<ipidsequence>`. These tags contain useful fingerprinting data about how a host generates TCP sequence numbers and IP IDs — useful for OS detection and network analysis. The data is silently dropped during parsing. There is a `# TODO` comment in `ivre/activecli.py` at line 439 acknowledging this gap.

**Match**  
The existing pattern for `osclass` and `osmatch` in `ivre/xmlnmap.py` around line 2133 is the model to follow:
```python
elif name in ["osclass", "osmatch"] and "os" in self._curhost:
    self._curhost["os"].setdefault(name, []).append(dict(attrs))
```
The same `startElement` method already handles `os`, `portused`, `osfingerprint`, and `trace` the same way — read the tag name, extract attributes, store them on `self._curhost`. The `tcpsequence` and `ipidsequence` tags follow the exact same pattern.

**Plan**  
In `ivre/xmlnmap.py`, inside the `startElement` method, add a new `elif` block after the `osfingerprint` handler (around line 2137):
```python
elif name in ["tcpsequence", "ipidsequence"]:
    self._curhost[name] = dict(attrs)
```
In `ivre/activecli.py`, replace the `# TODO` comment at line 439 with logic that reads and displays those fields from the host object.

**Review**  
- No `CONTRIBUTING.md` exists in the repo — followed conventions observed in the codebase (type hints, docstrings, existing code style)
- Linting workflow confirmed via `.github/workflows/linting.yml`
- Commit messages follow the pattern seen in the project history: short imperative summary

**Evaluate**  
- Added a sample Nmap XML snippet containing `<tcpsequence>` and `<ipidsequence>` tags to the test suite
- Ran `python tests/tests_no_backend.py` to confirm no regressions
- Manually verified the resulting host object contains both new fields

## Testing Strategy
- Added `NmapSequenceParsingTests` in `tests/tests_no_backend.py` with 3 tests:
  - `test_tcpsequence_stored`: verifies `tcpsequence` attributes are stored on host
  - `test_ipidsequence_stored`: verifies `ipidsequence` attributes are stored on host
  - `test_missing_sequence_tags_no_error`: verifies hosts without these tags parse cleanly
- All 3 new tests pass
- Full test suite: 366 existing tests still passing, 12 pre-existing failures confirmed unrelated (nmap not installed, screenshot handling)
- Black formatting verified clean on all modified files

## Linting
- Black formatting applied and verified clean
- flake8 E501 errors are all pre-existing in unchanged lines per project conventions

## Challenges Faced
- **Git setup**: Git was not installed initially on Windows; resolved by installing Git for Windows and switching to GitHub Codespaces
- **Branch naming**: The repo uses `master` not `main` — learned this early when `git checkout main` failed
- **Test infrastructure**: Writing tests required subclassing `NmapHandler` without a real database backend, which needed careful matching of internal attribute names (e.g. `_needports` vs `needports`)
- **Variable shadowing**: Named a parameter `xml` which shadowed the `xml` module import — fixed by renaming the import to `xml_sax`
- **Black formatting**: Had to run Black separately on the test file to meet the project's required formatting standard
- **Branch visibility**: The `fix-issue-ivre` branch wasn't appearing in GitHub's upstream compare dropdown; resolved by navigating directly to the fork's `/branches` page and opening the PR from there

## Feedback Received / Next Steps
- PR #1911 is open and awaiting maintainer review
- Will respond to any requested changes promptly and iterate on the branch

## Status
🟡 **Awaiting Review**

## Branch
https://github.com/chjohn5577/ivre/tree/fix-issue-ivre