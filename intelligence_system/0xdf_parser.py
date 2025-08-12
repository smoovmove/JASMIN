#0xdf parser

import feedparser
import requests
import os
import time
from bs4 import BeautifulSoup
import re
import markdownify

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
        code_language='',               # Don't add language to code blocks by default
        strip=['script', 'style'],      # Remove script and style tags
    )

# Add basic politeness
headers = {'User-Agent': 'Mozilla/5.0 (compatible; Educational scraper)'}

# Load the feed file
with open("0xdf_feed.txt", "r", encoding="utf-8") as f:
    feed_content = f.read()

feed = feedparser.parse(feed_content)
os.makedirs("0xdf_writeups", exist_ok=True)

# Create custom converter
converter = customize_converter()

for i, entry in enumerate(feed.entries, 1):
    title = entry.title.replace("/", "-").replace("\\", "-")
    # Clean up more filename characters
    title = re.sub(r'[<>:"|?*]', '-', title)
    
    link = entry.link
    filepath = os.path.join("0xdf_writeups", f"{title}.md")
    
    # Skip if already exists
    if os.path.exists(filepath):
        print(f"[{i}/{len(feed.entries)}] Already exists: {title}")
        continue
        
    print(f"[{i}/{len(feed.entries)}] Downloading: {title}")
    
    try:
        response = requests.get(link, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Extract metadata
        metadata = extract_metadata(soup)
        
        # Extract main content
        content = extract_writeup_content(soup)
        
        # Convert to markdown
        markdown_content = converter.convert(str(content))
        
        # Clean up the markdown
        clean_content = clean_markdown(markdown_content)
        
        # Create the final markdown file
        with open(filepath, "w", encoding="utf-8") as out_file:
            # Write frontmatter
            out_file.write("---\n")
            out_file.write(f"title: {entry.title}\n")
            out_file.write(f"url: {link}\n")
            out_file.write(f"date: {entry.published if hasattr(entry, 'published') else 'Unknown'}\n")
            
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
            
        print(f"✓ Saved to {filepath}")
        time.sleep(1)  # Be nice to the server
        
    except Exception as e:
        print(f"✗ Failed to download {link}: {e}")

print("Done scraping all write-ups!")