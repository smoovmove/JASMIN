#!/usr/bin/env python3
"""
Script to move all JARVIS-to-JASMIN backup files to a centralized backup location
Usage: python move_all_backups.py
"""

import os
import shutil
from pathlib import Path
from datetime import datetime

def create_backup_structure(target_dir):
    """Create organized backup directory structure"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_session_dir = target_dir / f"jarvis_to_jasmin_conversion_{timestamp}"
    backup_session_dir.mkdir(parents=True, exist_ok=True)
    return backup_session_dir

def find_all_backup_files(root_path):
    """Find all backup files from the conversion process"""
    backup_files = []
    backup_extensions = ['.backup', '.fix_backup', '.tmp', '.bak']
    
    for root, dirs, files in os.walk(root_path):
        # Skip hidden directories and common ignore patterns
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['__pycache__', 'node_modules']]
        
        for file in files:
            file_path = Path(root) / file
            
            # Check for backup files by extension
            if any(file.endswith(ext) for ext in backup_extensions):
                backup_files.append(file_path)
            
            # Check for sed backup files (like file.py.tmp)
            elif '.tmp' in file or '.bak' in file:
                backup_files.append(file_path)
    
    return backup_files

def categorize_backup_files(backup_files):
    """Categorize backup files by type"""
    categories = {
        'rename_backups': [],      # .backup files from rename script
        'fix_backups': [],         # .fix_backup files from fix script  
        'temp_files': [],          # .tmp, .bak files
        'other_backups': []        # anything else
    }
    
    for file_path in backup_files:
        if file_path.name.endswith('.backup'):
            categories['rename_backups'].append(file_path)
        elif file_path.name.endswith('.fix_backup'):
            categories['fix_backups'].append(file_path)
        elif any(file_path.name.endswith(ext) for ext in ['.tmp', '.bak']):
            categories['temp_files'].append(file_path)
        else:
            categories['other_backups'].append(file_path)
    
    return categories

def move_backup_file(backup_file, target_session_dir, root_path, category):
    """Move a single backup file maintaining directory structure"""
    try:
        # Get relative path from root
        try:
            rel_path = backup_file.relative_to(root_path)
        except ValueError:
            # If file is outside root_path, use just the filename
            rel_path = Path(backup_file.name)
        
        # Create category subdirectory
        category_dir = target_session_dir / category
        target_file = category_dir / rel_path
        
        # Create parent directories
        target_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Move the file
        shutil.move(str(backup_file), str(target_file))
        
        return target_file, None
        
    except Exception as e:
        return None, str(e)

def create_backup_inventory(target_session_dir, moved_files_by_category, errors):
    """Create a detailed inventory file of what was moved"""
    inventory_file = target_session_dir / "backup_inventory.txt"
    
    total_moved = sum(len(files) for files in moved_files_by_category.values())
    
    with open(inventory_file, 'w') as f:
        f.write(f"JARVIS to JASMIN Conversion - Backup Inventory\n")
        f.write(f"Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total files moved: {total_moved}\n")
        f.write(f"Errors encountered: {len(errors)}\n")
        f.write("\n" + "="*70 + "\n")
        
        # Write by category
        for category, moved_files in moved_files_by_category.items():
            if moved_files:
                f.write(f"\n{category.upper().replace('_', ' ')} ({len(moved_files)} files):\n")
                f.write("-" * 40 + "\n")
                for original, target in moved_files:
                    f.write(f"FROM: {original}\n")
                    f.write(f"TO:   {target}\n")
                    f.write("\n")
        
        if errors:
            f.write(f"\nERRORS ({len(errors)}):\n")
            f.write("-" * 20 + "\n")
            for file_path, error in errors:
                f.write(f"FILE: {file_path}\n")
                f.write(f"ERROR: {error}\n")
                f.write("\n")
    
    return inventory_file

def main():
    """Main function"""
    print("📦 JARVIS-to-JASMIN Backup File Organizer")
    print("=" * 50)
    
    # Define paths
    root_path = Path.cwd()
    target_base_dir = Path("/home/saint/jarvis_backups")
    
    print(f"Source directory: {root_path}")
    print(f"Target directory: {target_base_dir}")
    
    # Find all backup files
    print(f"\n🔍 Searching for backup files in {root_path}...")
    backup_files = find_all_backup_files(root_path)
    
    if not backup_files:
        print("✅ No backup files found!")
        return
    
    # Categorize backup files
    categories = categorize_backup_files(backup_files)
    
    print(f"\n📊 Found {len(backup_files)} backup files:")
    for category, files in categories.items():
        if files:
            print(f"  📁 {category.replace('_', ' ').title()}: {len(files)} files")
            for file_path in files[:3]:  # Show first 3 files
                print(f"    • {file_path}")
            if len(files) > 3:
                print(f"    • ... and {len(files) - 3} more")
    
    # Confirm operation
    choice = input(f"\nMove all {len(backup_files)} backup files to {target_base_dir}? (y/N): ").strip().lower()
    if choice not in ['y', 'yes']:
        print("Operation cancelled.")
        return
    
    # Create organized backup directory
    print(f"\n📁 Creating backup directory structure...")
    target_session_dir = create_backup_structure(target_base_dir)
    print(f"Backup session directory: {target_session_dir}")
    
    # Move files by category
    print(f"\n📦 Moving backup files...")
    moved_files_by_category = {category: [] for category in categories.keys()}
    errors = []
    
    for category, files in categories.items():
        if files:
            print(f"\n📁 Moving {category.replace('_', ' ')}...")
            for backup_file in files:
                print(f"  Moving: {backup_file.name}")
                target_file, error = move_backup_file(backup_file, target_session_dir, root_path, category)
                
                if error:
                    print(f"    ✗ Error: {error}")
                    errors.append((backup_file, error))
                else:
                    print(f"    ✓ Moved to: {category}/{backup_file.name}")
                    moved_files_by_category[category].append((backup_file, target_file))
    
    # Create inventory
    print(f"\n📋 Creating backup inventory...")
    inventory_file = create_backup_inventory(target_session_dir, moved_files_by_category, errors)
    print(f"Inventory saved: {inventory_file}")
    
    # Summary
    total_moved = sum(len(files) for files in moved_files_by_category.values())
    
    print("\n" + "=" * 50)
    print("✅ SUMMARY")
    print(f"Files successfully moved: {total_moved}")
    print(f"Errors encountered: {len(errors)}")
    print(f"Backup location: {target_session_dir}")
    
    if errors:
        print(f"\n⚠️  {len(errors)} files had errors:")
        for file_path, error in errors:
            print(f"  • {file_path.name}: {error}")
    
    print(f"\n📂 Directory structure created:")
    for category, files in moved_files_by_category.items():
        if files:
            print(f"  📁 {target_session_dir}/{category}/ - {len(files)} files")
    
    print(f"\n📋 Full inventory: {inventory_file}")
    
    # Cleanup suggestions
    if total_moved > 0:
        print(f"\n💡 Next steps:")
        print(f"1. Test JASMIN to ensure everything works correctly")
        print(f"2. If everything works, you can safely delete the backup directory")
        print(f"3. Backup directory: {target_session_dir}")
        print(f"4. To remove backups later: rm -rf {target_session_dir}")

if __name__ == "__main__":
    main()