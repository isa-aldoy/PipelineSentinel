# PipelineSentinel
Offline GitHub Actions security policy checker.

## Run
```sh
pip install -r requirements.txt
python sentinel.py examples/unsafe.yml --json
python -m unittest discover -s tests -v
```
Scans risky permissions, unpinned actions, privileged triggers with untrusted checkouts/expressions and literal credentials. Returns nonzero for findings at selected severity. Static heuristic scanner, not a full security audit.
