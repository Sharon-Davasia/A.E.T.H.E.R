# AETHER native synthetic fixture

`aether_fixture.py` is the actual native Windows fixture for Phase 3
acceptance preparation (F14). Pure Python 3.12 + ctypes over standard
Win32 controls — no GUI framework, no installer, no elevation, no
network, no real documents or settings.

Run (later, owner-side, only under the reviewed activation decision):

```
py -3.12 aether_fixture.py            # normal mode
py -3.12 aether_fixture.py --delayed  # Increment stalls 10 s (timeout tests)
```

Controls: status `Count: N` (id 101), Increment (102), disabled
button (103), synthetic password edit (104), modal-dialog trigger
(105), control replacement (106 — destroys/recreates Increment, new
UIA runtime identity), deterministic Reset (107).

UIA runtime identifiers are observed from the real snapshot at
acceptance time; the Linux fake identifiers (`fixture-increment`,
`fixture-status`) are a simulated contract only and are never assumed
to equal native identities. Fixture identity is established through
trusted launch/process evidence and the approved executable identity,
never through the window title.

## Reproducibly built executable (G05)

`AetherFixture.cs` + `build_fixture.cmd` build `AETHERFixture.exe`
with the in-box .NET Framework `csc.exe` (no downloads or new
dependencies). The approved launcher launches only that built
executable identity via `approved_executable` with no arguments;
the Python fixture source remains a contract reference and is never
launched as a script. Delayed response is the on-window
delay-toggle control (108), not a command-line argument.
