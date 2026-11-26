# Phase 3 Dependency Verification Report (CP0–CP2)

Verified against PyPI metadata on 2026-11-15 (planning/implementation
checkpoint). Versions are proposals until pinned in `backend/uv.lock`.

| Package | Version checked | Python/Windows | Licence | Transitives | Decision |
|---|---|---|---|---|---|
| RapidFuzz | 3.14.6 | `>=3.11`, platform-independent (wheels incl. Linux/Windows) | MIT (`license_expression: MIT`) | None by default (`numpy` only via optional `all` extra) | **Added CP2**: `rapidfuzz>=3.14,<4.0` in `backend/pyproject.toml`; exercised for real on Linux |
| pywin32 | 312 | `>=3.9`, Windows-only wheels | PSF | None | **Added in the foundation-closeout batch**: native AppsFolder discovery via Shell COM and the pointer-width-safe ctypes surface genuinely require it; `pywin32>=312,<313; sys_platform == 'win32'` in `backend/pyproject.toml`, resolved in `backend/uv.lock` (43 packages). Not installed or exercised in the Linux sandbox; no native evidence is claimed from it. |
| pywinauto | 0.6.9 | Windows (py>3.6: `pywin32`, `comtypes`; `six`) | BSD 3-clause | pywin32, comtypes (MIT), six | **Deferred** to CP4 UIA checkpoint; one UIA framework only |
| comtypes | 1.5.0 | `>=3.9` | MIT | None | Transitive of pywinauto only; not added directly |

No material deviation from the spec-selected stack was found, so per
the bounded authorization only the CP0–CP2-required dependency
(RapidFuzz) was added. Pinned Python (3.12.10 native / >=3.11) and
Node (22.22.3) versions are unchanged. `backend/uv.lock` was regenerated
(`uv lock`, RapidFuzz 3.14.6 added) alongside the pyproject constraint.
