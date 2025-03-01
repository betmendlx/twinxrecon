#!/usr/bin/env python3
# twinxrecon v1
# by betmen0x0

import subprocess
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
import time
import logging
import argparse
from colorama import init, Fore, Style
from tqdm import tqdm

init(autoreset=True)

parser = argparse.ArgumentParser(
    description="TwinXRecon v.1 - Recon with simple",
    epilog="Contoh penggunaan:\n  python3 twinxrecon.py -d example.com -t /home/twinxrecon/nuclei-templates/ -w 10\n",
    formatter_class=argparse.RawDescriptionHelpFormatter
)
parser.add_argument("-d", "--domain", required=True, help="Target domain (contoh: example.com)")
parser.add_argument("-t", "--templates", default="/home/user/nuclei-templates/", 
                    help="Path ke folder Nuclei templates")
parser.add_argument("-w", "--workers", type=int, default=10, help="Jumlah worker untuk paralelisme")
args = parser.parse_args()

DOMAIN = args.domain
NUCLEI_TEMPLATES = args.templates
MAX_WORKERS = args.workers
TEMP_DIR = f"temp_output_{DOMAIN}"
Path(TEMP_DIR).mkdir(exist_ok=True)

logging.basicConfig(filename=f"pentest_{DOMAIN}.log", level=logging.INFO, 
                    format="%(asctime)s - %(levelname)s - %(message)s")
logging.info("Memulai enumerasi untuk domain: %s", DOMAIN)

SUBFINDER_OUT = os.path.join(TEMP_DIR, f"tmp.{DOMAIN}.txt")
HTTPX_OUT = os.path.join(TEMP_DIR, f"sub.{DOMAIN}.txt")
WAYBACK_OUT = os.path.join(TEMP_DIR, f"tmp-urls.{DOMAIN}.txt")
URLS_OUT = os.path.join(TEMP_DIR, f"urls.{DOMAIN}.txt")
INFO_OUT = os.path.join(TEMP_DIR, f"info.{DOMAIN}.txt")
JS_OUT = os.path.join(TEMP_DIR, f"js.{DOMAIN}.txt")
SECRET_OUT = os.path.join(TEMP_DIR, f"secret.txt")

REQUIRED_TOOLS = ["subfinder", "httpx", "waybackurls", "uro", "secretfinder", "nuclei"]

summary = {
    "subdomains_found": 0,
    "live_subdomains": 0,
    "urls_collected": 0,
    "sensitive_files": 0,
    "js_files": 0,
    "secrets_found": {},
    "vulnerabilities": {"low": 0, "medium": 0, "high": 0, "critical": 0}
}

def check_dependencies():
    print(f"{Fore.YELLOW}Memeriksa dependensi tools...{Style.RESET_ALL}")
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool) is None:
            print(f"{Fore.RED}{tool} tidak ditemukan di PATH! Silakan install terlebih dahulu.{Style.RESET_ALL}")
            logging.error(f"{tool} tidak ditemukan")
            sys.exit(1)
    print(f"{Fore.GREEN}Semua tools tersedia!{Style.RESET_ALL}")
    logging.info("Semua tools tersedia")

def estimate_timeout(file_path):
    if not os.path.exists(file_path):
        return 120
    size = os.path.getsize(file_path) / 1024  # Size dalam KB
    return max(120, min(600, int(size / 10)))  # Minimum 120s, maksimum 600s

def run_command(command, output_file=None, input_file=None, timeout=300, retries=2):
    attempt = 0
    while attempt < retries:
        try:
            if output_file:
                with open(output_file, "w") as f:
                    if input_file:
                        with open(input_file, "r") as infile:
                            subprocess.run(command, shell=True, check=True, stdout=f, stdin=infile, timeout=timeout)
                    else:
                        subprocess.run(command, shell=True, check=True, stdout=f, timeout=timeout)
                os.chmod(output_file, 0o600)  # Keamanan file
            else:
                subprocess.run(command, shell=True, check=True, timeout=timeout)
            logging.info(f"Berhasil: {command}")
            print(f"{Fore.GREEN}Berhasil: {command}{Style.RESET_ALL}")
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            attempt += 1
            logging.warning(f"Attempt {attempt}/{retries} gagal untuk {command}: {e}")
            print(f"{Fore.YELLOW}Attempt {attempt}/{retries} gagal untuk {command}: {e}{Style.RESET_ALL}")
            time.sleep(2)
    logging.error(f"Gagal menjalankan {command} setelah {retries} percobaan")
    print(f"{Fore.RED}Gagal menjalankan {command} setelah {retries} percobaan{Style.RESET_ALL}")
    return False

def process_js_file(url, output_lock, pbar):
    command = f"secretfinder -i {url} -o cli"
    try:
        result = subprocess.check_output(command, shell=True, text=True, timeout=120)
        with output_lock:
            with open(SECRET_OUT, "a") as f:
                f.write(f"URL: {url}\n{result}\n{'='*50}\n")
            for service in ["aws", "twilio", "google", "heroku"]:
                if service in result.lower():
                    summary["secrets_found"][service] = summary["secrets_found"].get(service, 0) + 1
        pbar.update(1)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logging.error(f"Error memproses {url}: {e}")
        print(f"{Fore.RED}Error memproses {url}: {e}{Style.RESET_ALL}")
        pbar.update(1)

def main():
    check_dependencies()

    print(f"{Fore.MAGENTA}Menjalankan Subfinder...{Style.RESET_ALL}")
    if run_command(f"subfinder -d {DOMAIN} -all -recursive -o {SUBFINDER_OUT}", timeout=estimate_timeout(SUBFINDER_OUT)):
        summary["subdomains_found"] = sum(1 for _ in open(SUBFINDER_OUT) if _.strip())

    print(f"{Fore.BLUE}Menjalankan httpx...{Style.RESET_ALL}")
    if os.path.exists(SUBFINDER_OUT) and os.path.getsize(SUBFINDER_OUT) > 0:
        with open(SUBFINDER_OUT, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]
        chunk_size = max(1, len(subdomains) // MAX_WORKERS)
        chunks = [subdomains[i:i + chunk_size] for i in range(0, len(subdomains), chunk_size)]
        httpx_outputs = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for i, chunk in enumerate(chunks):
                chunk_file = os.path.join(TEMP_DIR, f"sub_chunk_{i}.txt")
                with open(chunk_file, "w") as f:
                    f.write("\n".join(chunk))
                output_chunk = os.path.join(TEMP_DIR, f"httpx_chunk_{i}.txt")
                httpx_outputs.append(output_chunk)
                executor.submit(run_command, f"httpx -l {chunk_file} -fc 403,404 -o {output_chunk}", 
                              timeout=estimate_timeout(chunk_file))
        with open(HTTPX_OUT, "w") as outfile:
            for chunk_out in httpx_outputs:
                if os.path.exists(chunk_out):
                    with open(chunk_out, "r") as infile:
                        outfile.write(infile.read())
        summary["live_subdomains"] = sum(1 for _ in open(HTTPX_OUT) if _.strip())

    print(f"{Fore.CYAN}Mengambil URL dari Wayback Machine...{Style.RESET_ALL}")
    run_command(f"cat {HTTPX_OUT} | waybackurls", output_file=WAYBACK_OUT, timeout=estimate_timeout(HTTPX_OUT))

    print(f"{Fore.GREEN}Memfilter URL dengan uro...{Style.RESET_ALL}")
    if run_command(f"cat {WAYBACK_OUT} | uro", output_file=URLS_OUT, timeout=estimate_timeout(WAYBACK_OUT)):
        summary["urls_collected"] = sum(1 for _ in open(URLS_OUT) if _.strip())

    print(f"{Fore.YELLOW}Mencari file sensitif...{Style.RESET_ALL}")
    grep_pattern = r"\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.rar|\.zip|\.config"
    run_command(f"cat {URLS_OUT} | grep -E '{grep_pattern}'", output_file=INFO_OUT, timeout=estimate_timeout(URLS_OUT))
    if os.path.exists(INFO_OUT) and os.path.getsize(INFO_OUT) > 0:
        summary["sensitive_files"] = sum(1 for _ in open(INFO_OUT) if _.strip())
        print(f"{Fore.GREEN}Ditemukan {summary['sensitive_files']} file sensitif, cek: {INFO_OUT}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}Tidak ada file sensitif yang ditemukan.{Style.RESET_ALL}")

    print(f"{Fore.MAGENTA}Mencari file JavaScript...{Style.RESET_ALL}")
    run_command(f"cat {URLS_OUT} | grep '.js$'", output_file=JS_OUT, timeout=estimate_timeout(URLS_OUT))
    if os.path.exists(JS_OUT) and os.path.getsize(JS_OUT) > 0:
        summary["js_files"] = sum(1 for _ in open(JS_OUT) if _.strip())

    if summary["js_files"] > 0:
        print(f"{Fore.BLUE}Memproses {summary['js_files']} file JS dengan SecretFinder...{Style.RESET_ALL}")
        with open(JS_OUT, "r") as f:
            js_urls = [line.strip() for line in f if line.strip()]
        output_lock = threading.Lock()
        with tqdm(total=len(js_urls), desc="Processing JS Files", 
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
            with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(js_urls))) as executor:
                executor.map(lambda url: process_js_file(url, output_lock, pbar), js_urls)

        if os.path.exists(SECRET_OUT):
            print(f"{Fore.CYAN}Mencari kredensial spesifik...{Style.RESET_ALL}")
            services = ["aws", "twilio", "google", "heroku"]
            for service in services:
                run_command(f"cat {SECRET_OUT} | grep -i {service}", 
                           output_file=os.path.join(TEMP_DIR, f"{service}_secrets.txt"),
                           timeout=estimate_timeout(SECRET_OUT))

    if input(f"{Fore.YELLOW}Lanjutkan ke Nuclei scanning? (y/n): {Style.RESET_ALL}").lower() == "y":
        print(f"{Fore.GREEN}Menjalankan Nuclei untuk deteksi kerentanan...{Style.RESET_ALL}")
        severities = ["low", "medium", "high", "critical"]
        for severity in severities:
            output_file = os.path.join(TEMP_DIR, f"nuclei_{severity}.txt")
            print(f"{Fore.YELLOW}Scanning dengan severity {severity}...{Style.RESET_ALL}")
            if run_command(f"nuclei -l {URLS_OUT} -t {NUCLEI_TEMPLATES} -ept ssl -s {severity} -o {output_file}",
                          timeout=estimate_timeout(URLS_OUT)):
                if os.path.exists(output_file):
                    with open(output_file, "r") as f:
                        summary["vulnerabilities"][severity] = sum(1 for line in f if line.strip())
    else:
        print(f"{Fore.RED}Scanning Nuclei dilewati.{Style.RESET_ALL}")

def cleanup():
    print(f"{Fore.RED}Membersihkan file sementara...{Style.RESET_ALL}")
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)
        print(f"{Fore.GREEN}Pembersihan selesai.{Style.RESET_ALL}")
        logging.info("Pembersihan selesai")
    else:
        print(f"{Fore.YELLOW}Tidak ada file sementara untuk dibersihkan.{Style.RESET_ALL}")

def print_summary():
    print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Summary Eksekusi untuk {DOMAIN} ==={Style.RESET_ALL}")
    print(f"{Fore.GREEN}Subdomains Found: {summary['subdomains_found']}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Live Subdomains: {summary['live_subdomains']}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}URLs Collected: {summary['urls_collected']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Sensitive Files Found: {summary['sensitive_files']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}JS Files Found: {summary['js_files']}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}Secrets Found:{Style.RESET_ALL}")
    for service, count in summary["secrets_found"].items():
        print(f"  - {service}: {count}")
    print(f"{Fore.RED}Vulnerabilities (Nuclei):{Style.RESET_ALL}")
    for severity, count in summary["vulnerabilities"].items():
        bar = "#" * (count // 5) if count > 0 else "-"
        print(f"  - {severity:<8}: {bar} ({count})")
    print(f"{Fore.CYAN}{Style.BRIGHT}============================{Style.RESET_ALL}")
    logging.info("Summary: %s", summary)

if __name__ == "__main__":
    try:
        main()
        print_summary()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Proses dihentikan oleh pengguna.{Style.RESET_ALL}")
        logging.warning("Proses dihentikan oleh pengguna")
    except Exception as e:
        print(f"{Fore.RED}Error tak terduga: {e}{Style.RESET_ALL}")
        logging.error(f"Error tak terduga: {e}")
    finally:
        cleanup()
