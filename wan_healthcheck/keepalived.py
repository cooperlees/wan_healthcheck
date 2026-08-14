"""The keepalived side: a track file whose value moves the VRRP priority."""

from pathlib import Path


def state_since(track_file: Path, fallback: float) -> float:
    """When the failover state was last set, from the track file's mtime.

    Better than an in-process timestamp: the file is only rewritten when the
    value actually changes, so its mtime *is* the last transition - and it
    survives daemon restarts, which an in-process value does not (every
    ansible_shed redeploy would otherwise reset the clock). It lives on
    tmpfs, so a reboot correctly resets it to the tmpfiles.d creation time.
    """
    try:
        return track_file.stat().st_mtime
    except OSError:
        return fallback


def write_track_file(path: Path, value: int) -> bool:
    """Atomically write keepalived's track_file; returns True if it changed.

    Compared stripped, not byte-for-byte: systemd-tmpfiles seeds the file as
    a bare "0" with no trailing newline, so an exact match would rewrite it
    on the first armed tick purely over whitespace - bumping the mtime that
    state_since() reads and making it look like a transition happened.
    """
    text = f"{value}\n"
    try:
        if path.read_text().strip() == str(value):
            return False
    except OSError:
        pass
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text)
    tmp.replace(path)
    return True
