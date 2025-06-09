#scrape_html.py

import requests
from pathlib import Path 

def load_sitemap(file_path ="0xdf_sitemap.txt"):
    with open(file_path, "r", encoding="utf-8") as f: 
        return [line.strip() for line in f if line.startswith("http")]
    
def download_all(posts, save_dir="/root/Documents/0xdf_html"):
    save_path = Path(save_dir)
    save_path.mkdir(parents=True, exist_ok=True)
    
    for url in posts: 
        slug = url.rstrip("/").split("/")[-1]
        filename = save_path / f"{slug}.html"
        try: 
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            filename.write_text(r.text, encoding="utf-8")
            print(f"Saved: {filename}")
        except Exception as e: 
            print(f"[!] Failed: {url} - {e}")
            
if __name__ == "__main__":
    urls = load_sitemap("0xdf_sitemap.txt")
    htb_urls = [url for url in urls if "htb-" in url]
    print(f"[+] Found {len(htb_urls)} HTB posts")
    download_all(htb_urls)