import base64
import csv
import glob
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


# ============================================================
# APP CONFIG
# ============================================================

APP_TITLE = "YOUTUBE SCRAPER & DOWNLOADER PRO (Termux)"
APP_ID = "youtube-scraper-downloader-pro"

_STORAGE_DL = os.path.expanduser("~/storage/downloads")

DEFAULT_OUTPUT = os.path.join(
    _STORAGE_DL if os.path.isdir(_STORAGE_DL) else os.path.expanduser("~"),
    "YoutubeDownloader",
)


# ============================================================
# LICENSE CONFIG
# ============================================================

PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAI8COWafKSK7Jv6Vn6Ptrajn0ETOa5M5kbPnbeIH/4Vc=
-----END PUBLIC KEY-----"""

LICENSE_DIR = os.path.join(os.path.expanduser("~"), ".afkar_youtube_license")
LICENSE_FILE = os.path.join(LICENSE_DIR, "license.key")
CLOCK_FILE = os.path.join(LICENSE_DIR, "clock.dat")
MACHINE_FILE = os.path.join(LICENSE_DIR, "machine.id")

VALID_PLANS = {"1 Hari", "1 Minggu", "1 Bulan", "1 Tahun", "Lifetime"}


CONTACT_EMAIL = "rendiafkar.tools@gmail.com"


def print_contact():
    print(f"Hubungi : {CONTACT_EMAIL}")
    print("  - Kirim Machine ID untuk meminta License Key")
    print("  - Hubungi juga untuk perpanjangan License Key")


# ============================================================
# MACHINE ID
# ============================================================

def get_machine_id():
    """
    Di Android/Termux uuid.getnode() tidak stabil (MAC address
    disembunyikan), jadi dipakai ID acak yang disimpan sekali
    di file lalu di-hash. Kalau data Termux dihapus, Machine ID
    ikut berubah dan license harus dibuat ulang.
    """
    os.makedirs(LICENSE_DIR, exist_ok=True)

    if os.path.exists(MACHINE_FILE):
        with open(MACHINE_FILE, "r", encoding="utf-8") as f:
            raw_id = f.read().strip()
    else:
        raw_id = ""

    if not raw_id:
        raw_id = secrets.token_hex(16)
        with open(MACHINE_FILE, "w", encoding="utf-8") as f:
            f.write(raw_id)

    raw = f"{raw_id}|{platform.system()}|{platform.machine()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ============================================================
# BASE64
# ============================================================

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode_strict(value):
    if not value:
        raise ValueError("Base64 kosong.")

    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("Format Base64 license tidak valid.")

    padding = "=" * (-len(value) % 4)
    decoded = base64.urlsafe_b64decode(value + padding)

    if b64url_encode(decoded) != value:
        raise ValueError("Base64 license tidak canonical.")

    return decoded


# ============================================================
# DATETIME
# ============================================================

def parse_iso_datetime(value):
    if value is None:
        return None
    if not value:
        raise ValueError("Tanggal license kosong.")

    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        raise ValueError("Format tanggal tidak valid.")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def format_license_date(dt):
    if dt is None:
        return "Lifetime"
    try:
        return dt.astimezone(timezone.utc).strftime("%d-%m-%Y %H:%M UTC")
    except Exception:
        return "Tanggal tidak valid"


def get_remaining_days(expires_at):
    if expires_at is None:
        return None
    seconds = (expires_at - datetime.now(timezone.utc)).total_seconds()
    if seconds <= 0:
        return 0
    return int(seconds / 86400) + 1


# ============================================================
# CLOCK ROLLBACK PROTECTION
# ============================================================

def check_clock_rollback(now=None):
    if now is None:
        now = datetime.now(timezone.utc)

    now_ts = now.timestamp()

    try:
        os.makedirs(LICENSE_DIR, exist_ok=True)

        previous = None

        if os.path.exists(CLOCK_FILE):
            with open(CLOCK_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    previous = float(content)

        if previous is not None:
            # Mundur lebih dari 5 menit
            if now_ts < previous - 300:
                return False
            # Mundur sedikit
            if now_ts < previous:
                return True

        with open(CLOCK_FILE, "w", encoding="utf-8") as f:
            f.write(str(max(now_ts, previous or 0)))

        return True

    except Exception:
        return False


# ============================================================
# VERIFY LICENSE
# ============================================================

def verify_license_key(license_key):
    try:
        if not license_key:
            return False, "License kosong.", None

        license_key = license_key.strip()

        if not license_key.startswith("AFKAR-"):
            return False, "Prefix license tidak valid.", None

        parts = license_key[6:].split(".")

        if len(parts) != 2:
            return False, "Format license tidak valid.", None

        payload_bytes = b64url_decode_strict(parts[0])
        signature = b64url_decode_strict(parts[1])

        if len(signature) != 64:
            return False, "Signature license tidak valid.", None

        # Verifikasi signature lebih dulu
        public_key = serialization.load_pem_public_key(PUBLIC_KEY_PEM)

        try:
            public_key.verify(signature, payload_bytes)
        except InvalidSignature:
            return False, "Signature license tidak valid.", None

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            return False, "Payload license rusak.", None

        if not isinstance(payload, dict):
            return False, "Payload license tidak valid.", None

        for field in ("app_id", "license_id", "plan",
                      "machine_id", "created_at", "expires_at"):
            if field not in payload:
                return False, f"Field license hilang: {field}", None

        if payload.get("app_id") != APP_ID:
            return False, "License bukan untuk aplikasi ini.", None

        if payload.get("machine_id") != get_machine_id():
            return False, "License bukan untuk perangkat ini.", None

        plan = payload.get("plan")

        if plan not in VALID_PLANS:
            return False, "Plan license tidak valid.", None

        try:
            created_at = parse_iso_datetime(payload.get("created_at"))
        except Exception:
            return False, "Tanggal pembuatan license tidak valid.", None

        expires_raw = payload.get("expires_at")

        if plan == "Lifetime":
            if expires_raw is not None:
                return False, "License Lifetime memiliki tanggal expired.", None
            expires_at = None
        else:
            if expires_raw is None:
                return False, "License berjangka tidak memiliki expired.", None
            try:
                expires_at = parse_iso_datetime(expires_raw)
            except Exception:
                return False, "Tanggal expired license tidak valid.", None

        now = datetime.now(timezone.utc)

        if not check_clock_rollback(now):
            return False, "Waktu perangkat terdeteksi mundur.", None

        if now < created_at:
            return False, "Waktu perangkat tidak valid.", None

        if expires_at is not None and now >= expires_at:
            return False, "License sudah expired.", None

        info = {
            "payload": payload,
            "created_at": created_at,
            "expires_at": expires_at,
        }

        return True, "License aktif.", info

    except Exception as e:
        return False, f"License tidak valid: {e}", None


# ============================================================
# LICENSE FILE
# ============================================================

def save_license_key(license_key):
    try:
        os.makedirs(LICENSE_DIR, exist_ok=True)
        with open(LICENSE_FILE, "w", encoding="utf-8") as f:
            f.write(license_key.strip())
        return True
    except Exception:
        return False


def load_saved_license():
    try:
        if not os.path.exists(LICENSE_FILE):
            return ""
        with open(LICENSE_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""


def get_license_info():
    key = load_saved_license()
    if not key:
        return None
    valid, _message, info = verify_license_key(key)
    return info if valid else None


def print_license_status(info):
    payload = info["payload"]
    plan = payload.get("plan", "-")
    expires = info["expires_at"]

    print(f"License : AKTIF | Plan: {plan}")
    print(f"Expired : {format_license_date(expires)}")

    if expires is None:
        print("Sisa    : Tidak terbatas")
    else:
        print(f"Sisa    : {get_remaining_days(expires)} hari")


def activate_license_flow():
    print("\n--- AKTIVASI LICENSE ---")
    print("Machine ID perangkat ini:\n")
    print(get_machine_id())
    print()
    print_contact()
    print()

    key = input("Tempel License Key (kosong = batal): ").strip()
    if not key:
        return False

    valid, message, info = verify_license_key(key)
    if not valid:
        print(f"\n[X] {message}")
        return False

    if not save_license_key(key):
        print("\n[X] License valid, tetapi gagal menyimpan.")
        return False

    print("\n[OK] License berhasil diaktifkan.")
    print_license_status(info)
    return True


def require_license():
    """Dipanggil sebelum scrape/download."""
    info = get_license_info()
    if info:
        return True

    print("\n[X] License belum aktif atau sudah expired.")
    print("    Pilih menu 1 untuk aktivasi.\n")
    print_contact()
    return False


# ============================================================
# HELPERS
# ============================================================

def clean_name(name):
    name = re.sub(r'[\\/:*?"<>|]+', "_", name)
    name = name.strip(" .")
    return name or "youtube_data"


def parse_range(start_value, end_value, total=None):
    try:
        start = int(start_value)
    except Exception:
        raise ValueError("Range awal harus berupa angka.")

    if start < 1:
        raise ValueError("Range awal minimal 1.")

    end_value = end_value.strip()

    if not end_value:
        end = total
    else:
        try:
            end = int(end_value)
        except Exception:
            raise ValueError("Range akhir harus berupa angka.")

    if end is not None and end < start:
        raise ValueError("Range akhir tidak boleh lebih kecil dari range awal.")

    return start, end


def get_ytdlp():
    return shutil.which("yt-dlp")


def get_ffmpeg():
    return shutil.which("ffmpeg")


def check_tools():
    if not get_ytdlp():
        print("\n[X] yt-dlp tidak ditemukan.")
        print("    Install dengan: pkg install yt-dlp")
        print("    atau          : pip install -U yt-dlp")
        return False

    if not get_ffmpeg():
        print("\n[!] ffmpeg tidak ditemukan. Video+audio tidak bisa digabung.")
        print("    Install dengan: pkg install ffmpeg")

    return True


def build_channel_url(value, content):
    value = value.strip()
    if not value:
        return None

    if value.startswith(("http://", "https://")):
        base = value.rstrip("/")
        if content == "shorts" and "/shorts" not in base:
            return base + "/shorts"
        return base

    handle = value if value.startswith("@") else "@" + value

    if content == "shorts":
        return f"https://www.youtube.com/{handle}/shorts"

    return f"https://www.youtube.com/{handle}/videos"


def default_csv_name(channel):
    value = channel.strip().lstrip("@")
    value = re.sub(r"[^A-Za-z0-9_-]+", "_", value)
    return "youtube_" + value if value else "youtube_data"


def ask(prompt, default=""):
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


# ============================================================
# SCRAPE
# ============================================================

def do_scrape(output_dir):
    if not require_license() or not check_tools():
        return

    channel = ask("Channel / @handle / URL (kosong = batal)")
    if not channel:
        return

    print("\nContent type:  1. videos   2. shorts")
    content = "shorts" if ask("Pilih", "1") == "2" else "videos"

    try:
        start, end = parse_range(
            ask("Scrape dari nomor", "1"),
            ask("Sampai nomor (kosong = semua)", ""),
        )
    except ValueError as e:
        print(f"\n[X] {e}")
        return

    base = clean_name(ask("Nama CSV", default_csv_name(channel)))
    url = build_channel_url(channel, content)

    print("\n" + "=" * 50)
    print("SCRAPE DIMULAI  (Ctrl+C untuk berhenti)")
    print("=" * 50)
    print(f"URL   : {url}")
    print(f"Range : {start} - {end if end else 'SEMUA'}\n")

    cmd = [
        get_ytdlp(),
        "--flat-playlist",
        "--ignore-errors",
        "--no-warnings",
        "--print",
        "%(webpage_url)s||%(title)s",
        url,
    ]

    rows = []
    count = 0
    proc = None
    cancelled = False

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

        for line in proc.stdout:
            line = line.strip()

            if not line or "||" not in line:
                continue

            video_url, title = [p.strip() for p in line.split("||", 1)]

            if not video_url:
                continue

            count += 1

            if count < start:
                continue

            if end is not None and count > end:
                break

            rows.append((video_url, title))
            print(f"[{count}] {title}")

    except KeyboardInterrupt:
        cancelled = True
        print("\n[!] Scrape dihentikan.")

    finally:
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.terminate()
                proc.wait(timeout=10)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    if cancelled and not rows:
        return

    if not rows:
        print("\nTidak ada data yang ditemukan.")
        return

    os.makedirs(output_dir, exist_ok=True)

    links_file = os.path.join(output_dir, f"links_{base}.csv")
    titles_file = os.path.join(output_dir, f"titles_{base}.csv")

    with open(links_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["URL"])
        for video_url, _title in rows:
            writer.writerow([video_url])

    with open(titles_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["Title"])
        for _video_url, title in rows:
            writer.writerow([title])

    print(f"\n[OK] Scrape selesai: {len(rows)} data.")
    print(f"Links  : {links_file}")
    print(f"Titles : {titles_file}")


# ============================================================
# DOWNLOAD
# ============================================================

def download_one(number, url, outdir):
    output_template = os.path.join(
        outdir, f"{number:03d}_%(title)s_[%(id)s].%(ext)s"
    )

    cmd = [
        get_ytdlp(),
        "--newline",
        "--no-warnings",
        "--continue",
        "--no-overwrites",
        "-f", "bv*+ba/best",
        "--merge-output-format", "mp4",
        "--windows-filenames",
        "--trim-filenames", "100",
        "-o", output_template,
        url,
    ]

    proc = None

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

        in_progress_line = False

        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue

            if line.startswith("[download]") and "%" in line:
                print("\r" + line[:75].ljust(75), end="", flush=True)
                in_progress_line = True
            else:
                if in_progress_line:
                    print()
                    in_progress_line = False
                print(f"[{number}] {line}")

        if in_progress_line:
            print()

        return proc.wait() == 0

    except KeyboardInterrupt:
        print(f"\n[!] Download #{number} dihentikan.")
        raise

    except Exception as e:
        print(f"[X] Download #{number}: {e}")
        return False

    finally:
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=10)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


def choose_csv(output_dir):
    files = sorted(glob.glob(os.path.join(output_dir, "links_*.csv")))

    if files:
        print("\nCSV links yang tersedia:")
        for i, path in enumerate(files, start=1):
            print(f"  {i}. {os.path.basename(path)}")
        print("  (atau ketik path CSV lengkap)")
        choice = input("Pilih nomor / path (kosong = batal): ").strip()
    else:
        print(f"\nTidak ada links_*.csv di {output_dir}")
        choice = input("Ketik path CSV (kosong = batal): ").strip()

    if not choice:
        return None

    if choice.isdigit() and files:
        idx = int(choice) - 1
        if 0 <= idx < len(files):
            return files[idx]
        print("[X] Nomor tidak valid.")
        return None

    path = os.path.expanduser(choice)
    if os.path.isfile(path):
        return path

    print("[X] File tidak ditemukan.")
    return None


def do_download(output_dir):
    if not require_license() or not check_tools():
        return

    csv_file = choose_csv(output_dir)
    if not csv_file:
        return

    urls = []

    with open(csv_file, "r", encoding="utf-8-sig", newline="") as f:
        for row in csv.reader(f):
            if not row:
                continue
            value = row[0].strip()
            if not value or value.lower() == "url":
                continue
            urls.append(value)

    if not urls:
        print("\n[X] Tidak ditemukan URL di dalam CSV.")
        return

    print(f"\nTotal URL di CSV: {len(urls)}")

    try:
        start, end = parse_range(
            ask("Download dari nomor", "1"),
            ask("Sampai nomor (kosong = semua)", ""),
            len(urls),
        )
    except ValueError as e:
        print(f"\n[X] {e}")
        return

    selected = urls[start - 1:end]
    total = len(selected)

    if total == 0:
        print("\n[X] Range di luar jumlah URL.")
        return

    base = clean_name(
        re.sub(r"^links_", "", os.path.splitext(os.path.basename(csv_file))[0])
    )
    outdir = os.path.join(output_dir, base)
    os.makedirs(outdir, exist_ok=True)

    print("\n" + "=" * 50)
    print("DOWNLOAD DIMULAI  (Ctrl+C untuk berhenti)")
    print("=" * 50)
    print(f"Total  : {total}")
    print(f"Range  : {start} - {end}")
    print(f"Output : {outdir}")
    print("Quality: Best Available")

    success = 0

    try:
        for index, url in enumerate(selected, start=start):
            print(f"\n>> Download #{index}")
            print(url)

            if download_one(index, url, outdir):
                success += 1
                print(f"[OK] Download #{index} selesai.")
            else:
                print(f"[X] Download #{index} gagal.")

    except KeyboardInterrupt:
        print("\n[!] Semua proses dihentikan.")

    print("\n" + "=" * 50)
    print(f"SELESAI: {success}/{total} berhasil")
    print(f"Output : {outdir}")
    print("=" * 50)


# ============================================================
# MAIN
# ============================================================

def main():
    output_dir = DEFAULT_OUTPUT

    print("=" * 56)
    print(f"  {APP_TITLE}")
    print("=" * 56)

    info = get_license_info()
    if info:
        print_license_status(info)
    else:
        print("[!] License belum aktif.")
        activate_license_flow()

    while True:
        print("\n" + "-" * 56)
        print(" 1. Aktivasi / cek license")
        print(" 2. Scrape channel -> CSV")
        print(" 3. Download dari CSV")
        print(" 4. Ubah folder output")
        print(" 0. Keluar")
        print("-" * 56)
        print(f"Output: {output_dir}")

        choice = input("Pilih menu: ").strip()

        if choice == "1":
            info = get_license_info()
            if info:
                print()
                print_license_status(info)
                print(f"\nMachine ID: {get_machine_id()}\n")
                print_contact()
            else:
                activate_license_flow()

        elif choice == "2":
            do_scrape(output_dir)

        elif choice == "3":
            do_download(output_dir)

        elif choice == "4":
            new_dir = ask("Folder output baru", output_dir)
            output_dir = os.path.expanduser(new_dir)

        elif choice == "0":
            print("Selesai.")
            return

        else:
            print("[X] Pilihan tidak valid.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nDibatalkan.")
