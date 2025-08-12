import requests
import os
import time
from bs4 import BeautifulSoup
import re
import markdownify
import xml.etree.ElementTree as ET

def extract_writeup_content(soup):
    """Extract main content from 0xdf's Jekyll site"""
    # Try 0xdf-specific selectors first
    content_selectors = [
        '#postBody',                    # Main content area
        '.post-content',                # Article content wrapper
        'article .post-content',        # More specific article content
        'article',                      # Fallback to article tag
        'main'                          # Last resort
    ]
    
    for selector in content_selectors:
        content = soup.select_one(selector)
        if content:
            return content
    
    # Final fallback to body if nothing found
    return soup.find('body') or soup

def extract_metadata(soup):
    """Extract metadata from the post"""
    metadata = {}
    
    # Extract title
    title_tag = soup.find('h1', class_='post-title')
    if title_tag:
        metadata['title'] = title_tag.get_text().strip()
    
    # Extract tags
    tag_elements = soup.find_all('a', class_='post-tag')
    if tag_elements:
        metadata['tags'] = [tag.get_text().strip() for tag in tag_elements]
    
    # Extract difficulty from box info table
    diff_span = soup.find('span', class_=lambda x: x and 'diff-' in x)
    if diff_span:
        metadata['difficulty'] = diff_span.get_text().strip()
    
    # Extract OS from box info
    os_cell = soup.find('td', string=lambda text: text and 'OS' in text)
    if os_cell and os_cell.find_next_sibling():
        os_text = os_cell.find_next_sibling().get_text().strip()
        if 'Windows' in os_text:
            metadata['os'] = 'Windows'
        elif 'Linux' in os_text:
            metadata['os'] = 'Linux'
    
    return metadata

def clean_markdown(markdown_text):
    """Clean up the generated markdown"""
    # Remove extra blank lines
    markdown_text = re.sub(r'\n\s*\n\s*\n+', '\n\n', markdown_text)
    
    # Fix spacing around code blocks
    markdown_text = re.sub(r'\n+```', '\n\n```', markdown_text)
    markdown_text = re.sub(r'```\n+', '```\n\n', markdown_text)
    
    # Clean up list formatting
    markdown_text = re.sub(r'\n\s*\n(\s*[-*+])', r'\n\1', markdown_text)
    markdown_text = re.sub(r'\n\s*\n(\s*\d+\.)', r'\n\1', markdown_text)
    
    return markdown_text.strip()

def customize_converter():
    """Create custom markdownify converter with better settings"""
    return markdownify.MarkdownConverter(
        heading_style=markdownify.ATX,  # Use # ## ### style headers
        bullets='-',                     # Use - for bullet points
        strip=['script', 'style']       # Remove script and style tags
    )

def parse_sitemap(sitemap_file):
    """Parse sitemap XML and extract writeup URLs"""
    urls = []
    
    try:
        tree = ET.parse(sitemap_file)
        root = tree.getroot()
        
        # Handle namespace
        namespace = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
        
        for url_elem in root.findall('ns:url', namespace):
            loc = url_elem.find('ns:loc', namespace)
            lastmod = url_elem.find('ns:lastmod', namespace)
            
            if loc is not None:
                url = loc.text
                date = lastmod.text if lastmod is not None else 'Unknown'
                
                # Filter for writeup URLs (exclude non-writeup pages)
                if ('/htb-' in url or '/vulnlab-' in url or '/thm-' in url or 
                    '/hackthebox' in url or '/tryhackme' in url or '/ctf-' in url):
                    urls.append({'url': url, 'date': date})
    
    except Exception as e:
        print(f"Error parsing sitemap: {e}")
        return []
    
    return urls

def get_title_from_url(url):
    """Extract a clean title from the URL for filename"""
    # Extract the part after the last slash and before .html
    filename = url.split('/')[-1].replace('.html', '')
    
    # Clean up for filesystem
    filename = filename.replace('-', ' ').title()
    filename = re.sub(r'[<>:"|?*]', '-', filename)
    
    return filename

# Add basic politeness
headers = {'User-Agent': 'Mozilla/5.0 (compatible; Educational scraper)'}

# Parse sitemap
print("Parsing sitemap...")
urls = parse_sitemap("sitemap.xml")

if not urls:
    print("No writeup URLs found in sitemap!")
    exit(1)

print(f"Found {len(urls)} writeup URLs")

# Ask user how many to process
try:
    max_count = int(input(f"How many writeups to process? (1-{len(urls)}, or 0 for all): "))
    if max_count == 0:
        max_count = len(urls)
    elif max_count > len(urls):
        max_count = len(urls)
except ValueError:
    print("Invalid input, processing all URLs")
    max_count = len(urls)

# Create output directory
os.makedirs("0xdf_writeups", exist_ok=True)

# Create custom converter
converter = customize_converter()

# Process URLs
processed_urls = urls[:max_count]
print(f"\nProcessing {len(processed_urls)} writeups...")

for i, url_data in enumerate(processed_urls, 1):
    url = url_data['url']
    date = url_data['date']
    
    title = get_title_from_url(url)
    filepath = os.path.join("0xdf_writeups", f"{title}.md")
    
    # Skip if already exists
    if os.path.exists(filepath):
        print(f"[{i}/{len(processed_urls)}] Already exists: {title}")
        continue
        
    print(f"[{i}/{len(processed_urls)}] Processing: {title}")
    print(f"  URL: {url}")
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Extract metadata
        metadata = extract_metadata(soup)
        
        # Extract main content
        content = extract_writeup_content(soup)
        
        if not content:
            print(f"  ⚠️  No content found with selectors!")
            continue
        
        # Convert to markdown
        markdown_content = converter.convert(str(content))
        
        # Clean up the markdown
        clean_content = clean_markdown(markdown_content)
        
        # Create the final markdown file
        with open(filepath, "w", encoding="utf-8") as out_file:
            # Write frontmatter
            out_file.write("---\n")
            out_file.write(f"title: {metadata.get('title', title)}\n")
            out_file.write(f"url: {url}\n")
            out_file.write(f"date: {date}\n")
            
            # Add extracted metadata
            if metadata.get('difficulty'):
                out_file.write(f"difficulty: {metadata['difficulty']}\n")
            if metadata.get('os'):
                out_file.write(f"os: {metadata['os']}\n")
            if metadata.get('tags'):
                out_file.write(f"tags: {', '.join(metadata['tags'])}\n")
                
            out_file.write("---\n\n")
            
            # Write the content
            out_file.write(clean_content)
            
        print(f"  ✓ Saved to {filepath}")
        
        time.sleep(1)  # Be nice to the server
        
    except Exception as e:
        print(f"  ✗ Failed to download {url}: {e}")
        print()

print(f"\n✅ Scraping complete! Processed {len(processed_urls)} writeups.")
print("Check the '0xdf_writeups' folder for the generated markdown files.")