#!/usr/bin/env python3
"""
Script to find and fix remaining JASMIN references that were missed
Usage: python find_remaining_jarvis.py
"""

import os
import re
import shutil
from pathlib import Path

def scan_file_for_jarvis(file_path):
    """Scan a file for any remaining JASMIN references"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Find all JASMIN-related patterns (case insensitive)
        patterns = [
            (r'\bjarvis_\w+', 'variable/method names with jarvis_'),
            (r'\.jasmin\b', 'dot notation .jasmin'),
            (r'\bjarvis\b(?!\s*=\s*["\'])', 'standalone jasmin words'),
            (r'JASMIN', 'uppercase JASMIN'),
            (r'Jasmin', 'title case Jasmin'),
        ]
        
        found_issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, description in patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    found_issues.append({
                        'line_num': line_num,
                        'line': line.strip(),
                        'match': match.group(),
                        'start': match.start(),
                        'end': match.end(),
                        'description': description
                    })
        
        return found_issues
        
    except Exception as e:
        print(f"Error scanning {file_path}: {e}")
        return []

def fix_jarvis_references(file_path, dry_run=False):
    """Fix JASMIN references in a file"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        original_content = content
        
        # More comprehensive replacement patterns
        replacements = [
            # Variable/method names
            (r'\bjarvis_env\b', 'jasmin_env'),
            (r'\bjarvis_config\b', 'jasmin_config'),
            (r'\bjarvis_manager\b', 'jasmin_manager'),
            (r'\bjarvis_session\b', 'jasmin_session'),
            (r'\bjarvis_payload\b', 'jasmin_payload'),
            (r'\bjarvis_intel\b', 'jasmin_intel'),
            (r'\bjarvis_(\w+)', r'jasmin_\1'),  # Any jasmin_something
            
            # Dot notation
            (r'\.jasmin\b', '.jasmin'),
            
            # Standalone references
            (r'\bJASMIN\b', 'JASMIN'),
            (r'\bJarvis\b', 'Jasmin'),
            (r'\bjarvis\b(?!\s*=\s*["\'])', 'jasmin'),  # Don't replace in string assignments
            
            # Comments and documentation
            (r'#.*JASMIN', lambda m: m.group().replace('JASMIN', 'JASMIN')),
            (r'#.*Jasmin', lambda m: m.group().replace('Jasmin', 'Jasmin')),
            (r'#.*jasmin', lambda m: m.group().replace('jasmin', 'jasmin')),
            
            # String literals (be more careful)
            (r'".*JASMIN.*"', lambda m: m.group().replace('JASMIN', 'JASMIN')),
            (r"'.*JASMIN.*'", lambda m: m.group().replace('JASMIN', 'JASMIN')),
        ]
        
        changes_made = False
        for pattern, replacement in replacements:
            if callable(replacement):
                # Handle lambda functions for complex replacements
                new_content = re.sub(pattern, replacement, content)
            else:
                new_content = re.sub(pattern, replacement, content)
            
            if new_content != content:
                changes_made = True
                content = new_content
        
        if changes_made:
            if not dry_run:
                # Create backup
                backup_path = str(file_path) + ".fix_backup"
                shutil.copy2(file_path, backup_path)
                
                # Write fixed content
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                return True, f"Fixed and backed up to {backup_path}"
            else:
                return True, "Would be fixed (dry run)"
        
        return False, "No changes needed"
        
    except Exception as e:
        return False, f"Error: {e}"

def find_text_files(root_path):
    """Find all relevant text files"""
    extensions = ['.py', '.txt', '.md', '.rst', '.yml', '.yaml', '.json', '.cfg', '.conf', '.sh', '.bat']
    
    text_files = []
    for root, dirs, files in os.walk(root_path):
        # Skip certain directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['__pycache__', 'node_modules']]
        
        for file in files:
            file_path = Path(root) / file
            
            # Skip backup files
            if file.endswith('.backup') or file.endswith('.fix_backup'):
                continue
            
            # Check by extension
            if any(file.lower().endswith(ext) for ext in extensions):
                text_files.append(file_path)
    
    return text_files

def main():
    """Main function"""
    print("🔍 Finding Remaining JASMIN References")
    print("=" * 40)
    
    root_path = Path.cwd()
    print(f"Scanning directory: {root_path}")
    
    # Find all text files
    text_files = find_text_files(root_path)
    print(f"Found {len(text_files)} files to scan")
    
    # Scan for issues
    print(f"\n🔍 Scanning for remaining JASMIN references...")
    all_issues = {}
    total_issues = 0
    
    for file_path in text_files:
        issues = scan_file_for_jarvis(file_path)
        if issues:
            all_issues[file_path] = issues
            total_issues += len(issues)
            print(f"  📄 {file_path}: {len(issues)} issues")
    
    if not all_issues:
        print("✅ No remaining JASMIN references found!")
        return
    
    print(f"\n📊 Summary: {total_issues} issues in {len(all_issues)} files")
    
    # Show detailed issues
    print(f"\n📋 Detailed Issues:")
    print("-" * 60)
    
    for file_path, issues in all_issues.items():
        print(f"\n📄 {file_path}:")
        for issue in issues[:5]:  # Show first 5 issues per file
            print(f"  Line {issue['line_num']}: {issue['match']} ({issue['description']})")
            print(f"    → {issue['line']}")
        
        if len(issues) > 5:
            print(f"    ... and {len(issues) - 5} more issues")
    
    # Ask to fix
    print(f"\n" + "=" * 60)
    choice = input(f"Fix all {total_issues} issues? (y/N): ").strip().lower()
    
    if choice not in ['y', 'yes']:
        print("No changes made.")
        return
    
    # Dry run first
    print(f"\n🧪 Dry run - checking what would be changed...")
    dry_run_results = {}
    
    for file_path in all_issues.keys():
        would_fix, message = fix_jarvis_references(file_path, dry_run=True)
        if would_fix:
            dry_run_results[file_path] = message
            print(f"  ✓ {file_path}: {message}")
    
    if not dry_run_results:
        print("❌ No files would be changed by the fix")
        return
    
    # Confirm actual fix
    confirm = input(f"\nApply fixes to {len(dry_run_results)} files? (y/N): ").strip().lower()
    if confirm not in ['y', 'yes']:
        print("Operation cancelled.")
        return
    
    # Apply fixes
    print(f"\n🔧 Applying fixes...")
    fixed_count = 0
    
    for file_path in all_issues.keys():
        was_fixed, message = fix_jarvis_references(file_path, dry_run=False)
        if was_fixed:
            print(f"  ✅ {file_path}: {message}")
            fixed_count += 1
        else:
            print(f"  ❌ {file_path}: {message}")
    
    print(f"\n🎉 Fixed {fixed_count} files!")
    print(f"💾 Backup files created with .fix_backup extension")
    
    # Suggest next steps
    print(f"\n💡 Next steps:")
    print(f"1. Test JASMIN to make sure everything works")
    print(f"2. If everything works, remove backup files:")
    print(f"   find . -name '*.fix_backup' -delete")

if __name__ == "__main__":
    main()