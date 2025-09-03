#!/usr/bin/env python3
import argparse
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
import getpass
from typing import Optional, Dict

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileMovedEvent
from watchdog.observers import Observer

DEFAULT_ROTATE_SECONDS = 60
STABLE_CHECKS = 3
STABLE_SLEEP = 1.0
UPLOAD_TIMEOUT = 300
PROCESSED_SUBDIR = "processed"
FAILED_SUBDIR = "failed"

logger = logging.getLogger("feed_caronte")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(ch)

def make_session(max_retries=5, backoff_factor=1.0, status_forcelist=(429, 500, 502, 503, 504), basic_auth: Optional[tuple]=None):
    s = requests.Session()
    retry = Retry(
        total=max_retries,
        read=max_retries,
        connect=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(['HEAD', 'GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE'])
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    if basic_auth:
        s.auth = basic_auth
    return s

def upload_file(session, file_path: Path, caronte_url: str, file_field: str = "file", extra_fields: Optional[Dict[str, str]] = None, timeout=UPLOAD_TIMEOUT):
    logger.info("Uploading %s -> %s", file_path, caronte_url)
    extra_fields = extra_fields or {}
    try:
        with file_path.open("rb") as fh:
            files = {file_field: (file_path.name, fh)}
            resp = session.post(caronte_url, files=files, data=extra_fields, timeout=timeout)
        if resp.status_code == 422:
            logger.error("Upload returned 422 Unprocessable Entity for %s", file_path)
            try:
                logger.error("Response body: %s", resp.text)
            except Exception:
                logger.error("Failed to read response text")
            return False
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as he:
            logger.exception("Upload failed for %s: HTTP %s", file_path, resp.status_code)
            try:
                logger.error("Response body: %s", resp.text)
            except Exception:
                pass
            return False
        logger.info("Upload OK: %s -> HTTP %s", file_path, resp.status_code)
        return True
    except requests.exceptions.RequestException as e:
        logger.exception("Request exception during upload for %s: %s", file_path, e)
        return False
    except Exception as e:
        logger.exception("Unexpected error during upload for %s: %s", file_path, e)
        return False

def wait_until_stable(path: Path, checks=STABLE_CHECKS, sleep=STABLE_SLEEP, max_wait=None):
    logger.debug("Waiting until file is stable: %s", path)
    last_size = -1
    stable_count = 0
    waited = 0.0
    while True:
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            logger.warning("File disappeared while waiting: %s", path)
            return False
        if size == last_size:
            stable_count += 1
        else:
            stable_count = 1
            last_size = size
        if stable_count >= checks:
            logger.debug("File size stable: %s size=%d", path, size)
            return True
        time.sleep(sleep)
        waited += sleep
        if max_wait is not None and waited >= max_wait:
            logger.warning("Max wait exceeded for %s", path)
            return False

class PcapHandler(FileSystemEventHandler):
    def __init__(self, session, caronte_url, outdir: Path, remove_after=True, move_after=True, processed_dir=None, failed_dir=None, file_field="file", extra_fields=None):
        super().__init__()
        self.session = session
        self.caronte_url = caronte_url
        self.outdir = outdir
        self.remove_after = remove_after
        self.move_after = move_after
        self.processed_dir = processed_dir or outdir / PROCESSED_SUBDIR
        self.failed_dir = failed_dir or outdir / FAILED_SUBDIR
        self.file_field = file_field
        self.extra_fields = extra_fields or {}
        self._lock = threading.Lock()
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        self.failed_dir.mkdir(parents=True, exist_ok=True)

    def _handle(self, src_path):
        p = Path(src_path)
        if p.is_dir():
            return
        if p.suffix in (".tmp", ".part"):
            logger.debug("Ignoring temporary file: %s", p)
            return
        if not wait_until_stable(p, checks=STABLE_CHECKS, sleep=STABLE_SLEEP, max_wait=300):
            logger.warning("File not stable or disappeared: %s", p)
            return
        success = upload_file(self.session, p, self.caronte_url, file_field=self.file_field, extra_fields=self.extra_fields)
        try:
            if success:
                dest = self.processed_dir / p.name if self.move_after else None
            else:
                dest = self.failed_dir / p.name if self.move_after else None
            if dest:
                logger.info("Moving %s -> %s", p, dest)
                shutil.move(str(p), str(dest))
            elif self.remove_after and success:
                logger.info("Removing uploaded file: %s", p)
                p.unlink(missing_ok=True)
        except Exception:
            logger.exception("Error while moving/removing file %s", p)

    def on_created(self, event):
        if isinstance(event, FileCreatedEvent):
            logger.info("Created event: %s", event.src_path)
            threading.Thread(target=self._handle, args=(event.src_path,), daemon=True).start()

    def on_moved(self, event):
        if isinstance(event, FileMovedEvent):
            logger.info("Moved event: %s -> %s", event.src_path, event.dest_path)
            threading.Thread(target=self._handle, args=(event.dest_path,), daemon=True).start()

def ensure_capture_running(iface: str, outdir: Path, rotate_seconds: int = None, max_size_mb: int = None, use_dumpcap=False, extra_args=None):
    bin_name = "dumpcap" if use_dumpcap else "tcpdump"
    if not shutil.which(bin_name):
        logger.error("%s not found in PATH. Install tcpdump or dumpcap.", bin_name)
        return None
    timestamp = "%Y%m%d-%H%M%S"
    filename = str(outdir / f"pcap-{timestamp}.pcap")
    cmd = [bin_name, "-i", iface, "-w", filename]
    if rotate_seconds:
        if not use_dumpcap:
            cmd += ["-G", str(int(rotate_seconds))]
        else:
            cmd += ["-b", f"duration:{int(rotate_seconds)}"]
    if max_size_mb:
        if not use_dumpcap:
            cmd += ["-C", str(int(max_size_mb))]
        else:
            cmd += ["-b", f"filesize:{int(max_size_mb)*1024}"]
    if extra_args:
        cmd += extra_args
    logger.info("Starting capture: %s", " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(outdir))
    logger.info("Started capture pid=%s", proc.pid)
    return proc

def parse_args():
    p = argparse.ArgumentParser(description="Capture, watch and upload pcaps to Caronte")
    p.add_argument("--iface", help="Interface for tcpdump (if omitted capture won't start)", default=None)
    p.add_argument("--outdir", "-d", required=True, help="Directory for pcap files")
    p.add_argument("--caronte", "-u", required=True, help="Caronte upload URL, e.g. http://localhost:3333/api/pcap/upload")
    p.add_argument("--rotate", type=int, default=DEFAULT_ROTATE_SECONDS, help="Rotate seconds for tcpdump (-G)")
    p.add_argument("--size", type=int, help="Rotate by size in MB (-C)")
    p.add_argument("--use-dumpcap", action="store_true", help="Use dumpcap instead of tcpdump")
    p.add_argument("--no-capture", action="store_true", help="Only watch and upload, do not start tcpdump")
    p.add_argument("--remove-after", action="store_true", help="Remove files after successful upload (otherwise moved to processed)")
    p.add_argument("--processed-subdir", default=PROCESSED_SUBDIR, help="Subdirectory for processed files (inside outdir)")
    p.add_argument("--failed-subdir", default=FAILED_SUBDIR, help="Subdirectory for failed uploads")
    p.add_argument("--max-retries", type=int, default=5, help="Max HTTP retries (requests retry)")
    p.add_argument("--backoff", type=float, default=1.0, help="Backoff factor for retry")
    p.add_argument("--user", "-U", help="Basic auth username for Caronte")
    p.add_argument("--password", "-P", help="Basic auth password (not recommended on CLI)")
    p.add_argument("--password-file", help="Read password from this file")
    p.add_argument("--password-env", default="CARONTE_PASSWORD", help="Environment variable to read password from (default: CARONTE_PASSWORD)")
    p.add_argument("--file-field", default="file", help="Form field name to use for file upload (default: file)")
    p.add_argument("--form-field", action="append", default=[], help="Additional form field in key=value format; repeatable")
    return p.parse_args()

def main():
    args = parse_args()
    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    processed_dir = outdir / args.processed_subdir
    failed_dir = outdir / args.failed_subdir

    basic_auth = None
    if args.user:
        passwd = None
        if args.password:
            passwd = args.password
        elif args.password_file:
            try:
                with open(args.password_file, "r", encoding="utf-8") as f:
                    passwd = f.read().strip()
            except Exception as e:
                logger.error("Failed to read password file: %s", e)
                sys.exit(2)
        else:
            passwd = os.environ.get(args.password_env)
        if not passwd:
            try:
                passwd = getpass.getpass("Caronte password for {}: ".format(args.user))
            except Exception:
                passwd = None
        if not passwd:
            logger.error("Password not provided (via --password, --password-file, env %s or prompt).", args.password_env)
            sys.exit(2)
        basic_auth = (args.user, passwd)

    extra_fields = {}
    for kv in args.form_field:
        if "=" in kv:
            k, v = kv.split("=", 1)
            extra_fields[k] = v
        else:
            logger.warning("Ignoring malformed form-field: %s", kv)

    session = make_session(max_retries=args.max_retries, backoff_factor=args.backoff, basic_auth=basic_auth)

    capture_proc = None
    if not args.no_capture and args.iface:
        capture_proc = ensure_capture_running(
            iface=args.iface,
            outdir=outdir,
            rotate_seconds=args.rotate,
            max_size_mb=args.size,
            use_dumpcap=args.use_dumpcap
        )
        if capture_proc is None:
            logger.error("Failed to start capture. Exiting.")
            sys.exit(1)

    event_handler = PcapHandler(session=session, caronte_url=args.caronte, outdir=outdir,
                                remove_after=args.remove_after, move_after=not args.remove_after,
                                processed_dir=processed_dir, failed_dir=failed_dir,
                                file_field=args.file_field, extra_fields=extra_fields)
    observer = Observer()
    observer.schedule(event_handler, str(outdir), recursive=False)
    observer.start()
    logger.info("Started watcher on %s", outdir)

    stop_event = threading.Event()

    def _stop(sig, frame):
        logger.info("Received signal %s, stopping...", sig)
        stop_event.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    try:
        while not stop_event.is_set():
            time.sleep(1)
    finally:
        logger.info("Shutting down observer...")
        observer.stop()
        observer.join(timeout=5)
        if capture_proc:
            logger.info("Terminating capture pid=%s", capture_proc.pid)
            capture_proc.terminate()
            try:
                capture_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.info("Killing capture pid=%s", capture_proc.pid)
                capture_proc.kill()

    logger.info("Exited.")

if __name__ == "__main__":
    main()
