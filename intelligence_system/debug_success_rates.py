#!/usr/bin/env python3

"""
Debug Success Rate Extraction
Investigate why all success rates are showing 0%
"""

import json
import sqlite3
from pathlib import Path
from collections import defaultdict

def debug_intelligence_data():
    """Debug the intelligence extraction format and success rate data"""
    
    print("🔍 DEBUGGING SUCCESS RATE EXTRACTION")
    print("=" * 50)
    
    # Check a few sample intelligence files
    intelligence_dir = Path("intelligence_db/intelligence")
    sample_files = list(intelligence_dir.glob("*.json"))[:5]
    
    print(f"📁 Analyzing {len(sample_files)} sample files...")
    print()
    
    for i, file_path in enumerate(sample_files, 1):
        print(f"📄 File {i}: {file_path.name}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Check structure
            print(f"   Top-level keys: {list(data.keys())}")
            
            # Check technique intelligence section
            tech_intel = data.get('technique_intelligence', {})
            if tech_intel:
                print(f"   Technique intelligence keys: {list(tech_intel.keys())}")
                
                # Check techniques
                techniques = tech_intel.get('techniques', [])
                print(f"   Techniques found: {len(techniques)}")
                
                for j, technique in enumerate(techniques[:3], 1):
                    if isinstance(technique, dict):
                        print(f"     Tech {j} keys: {list(technique.keys())}")
                        success_rate = technique.get('success_probability', 'NOT_FOUND')
                        success_rate2 = technique.get('success_rate', 'NOT_FOUND')
                        effectiveness = technique.get('effectiveness_rating', 'NOT_FOUND')
                        print(f"     Success probability: {success_rate}")
                        print(f"     Success rate: {success_rate2}")
                        print(f"     Effectiveness: {effectiveness}")
                
                # Check command sequences
                sequences = tech_intel.get('command_sequences', [])
                print(f"   Command sequences: {len(sequences)}")
                
                for j, seq in enumerate(sequences[:2], 1):
                    if isinstance(seq, dict):
                        success_rate = seq.get('success_rate', 'NOT_FOUND')
                        print(f"     Sequence {j} success rate: {success_rate}")
            
            # Check success patterns
            success_patterns = data.get('success_patterns', {})
            if success_patterns:
                print(f"   Success patterns keys: {list(success_patterns.keys())}")
                
                success_factors = success_patterns.get('success_factors', [])
                print(f"   Success factors: {len(success_factors)}")
                
                for factor in success_factors[:2]:
                    if isinstance(factor, dict):
                        success_prob = factor.get('success_probability', 'NOT_FOUND')
                        print(f"     Factor success probability: {success_prob}")
            
            print()
            
        except Exception as e:
            print(f"   ❌ Error reading file: {e}")
            print()

def debug_database_content():
    """Debug what's actually stored in the database"""
    
    print("🗄️ DEBUGGING DATABASE CONTENT")
    print("=" * 40)
    
    try:
        conn = sqlite3.connect("intelligence_db/intelligence.db")
        conn.row_factory = sqlite3.Row
        
        # Check techniques table
        techniques = conn.execute("""
            SELECT name, success_rate, difficulty, data_json 
            FROM techniques 
            LIMIT 10
        """).fetchall()
        
        print(f"📊 Sample techniques in database:")
        for i, tech in enumerate(techniques, 1):
            print(f"{i:2d}. {tech['name']:<30} Success: {tech['success_rate']} Difficulty: {tech['difficulty']}")
            
            # Check raw JSON data
            try:
                raw_data = json.loads(tech['data_json'])
                actual_success = raw_data.get('success_rate', 'NOT_FOUND')
                print(f"     Raw success_rate in JSON: {actual_success}")
            except:
                print(f"     Could not parse JSON data")
        
        print()
        
        # Check if success_rate column has any non-zero values
        stats = conn.execute("""
            SELECT 
                COUNT(*) as total_techniques,
                COUNT(CASE WHEN success_rate > 0 THEN 1 END) as non_zero_rates,
                AVG(success_rate) as avg_rate,
                MAX(success_rate) as max_rate
            FROM techniques
        """).fetchone()
        
        print(f"📈 Success Rate Statistics:")
        print(f"   Total techniques: {stats['total_techniques']}")
        print(f"   Non-zero rates: {stats['non_zero_rates']}")
        print(f"   Average rate: {stats['avg_rate']}")
        print(f"   Maximum rate: {stats['max_rate']}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Database debug failed: {e}")

def suggest_fixes():
    """Suggest fixes based on the debug findings"""
    
    print("\n💡 SUGGESTED FIXES")
    print("=" * 30)
    
    print("Based on the debug analysis, the issue is likely:")
    print()
    print("1. 🔍 SUCCESS RATE FIELD MAPPING:")
    print("   - Check if intelligence files use 'success_probability' vs 'success_rate'")
    print("   - Look for 'effectiveness_rating' as alternative")
    print("   - Verify numeric vs string format (0.75 vs '75%')")
    print()
    print("2. 🔧 EXTRACTION LOGIC:")
    print("   - Update _extract_techniques() to handle multiple field names")
    print("   - Add fallback values based on effectiveness ratings")
    print("   - Convert percentage strings to decimals")
    print()
    print("3. 📊 CALCULATION METHOD:")
    print("   - Use confidence scores as proxy success rates")
    print("   - Calculate based on technique frequency/popularity")
    print("   - Apply default rates based on attack complexity")
    
def main():
    debug_intelligence_data()
    debug_database_content()
    suggest_fixes()

if __name__ == "__main__":
    main()