# Windows Install Proof

Windows installer behavior is owned by `install.ps1` plus the Windows lanes in
CI. Repo-level scripts in this directory should exercise Windows-specific
install paths only; POSIX `install.sh` scenarios live under `tests/install/linux/`
and `tests/install/macos/`.
