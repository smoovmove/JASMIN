#!/usr/bin/env python3

"""
Intelligence Database Inspector
Analyzes and displays contents of the intelligence.db file built from 0xdf writeups
"""

import json
import sqlite3
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import Counter, defaultdict
from dataclasses import dataclass

@dataclass
class DatabaseSummary:
    """Summary of database contents"""
    total_scenarios: int
    total_techniques: int
    total_port_mappings: int
    total_service_mappings: int
    top_environments: Dict[str, int]
    top_techniques: Dict[str, int]
    port_coverage: Dict[int, int]
    service_coverage: Dict[str, int]
    complexity_distribution: Dict[str, int]
    canonical_groups: Dict[str, int]

class IntelligenceDatabaseInspector:
    """Inspector for intelligence database built from 0xdf writeups"""
    
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.conn = None
        self.summary = None
        
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {db_path}")
        
        self._connect_database()
    
    def _connect_database(self):
        """Connect to the database"""
        try:
            self.conn = sqlite3.connect(str(self.db_path))
            self.conn.row_factory = sqlite3.Row
            print(f"✅ Connected to database: {self.db_path}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to database: {e}")
    
    def inspect_database_structure(self):
        """Inspect the database structure and tables"""
        
        print("\n🔍 DATABASE STRUCTURE ANALYSIS")
        print("=" * 50)
        
        # Get all tables
        tables = self.conn.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name
        """).fetchall()
        
        print(f"📋 Tables found: {len(tables)}")
        
        for table in tables:
            table_name = table['name']
            
            # Get row count
            count = self.conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
            
            # Get column info
            columns = self.conn.execute(f"PRAGMA table_info({table_name})").fetchall()
            column_names = [col['name'] for col in columns]
            
            print(f"\n📊 {table_name.upper()}")
            print(f"   Rows: {count:,}")
            print(f"   Columns: {', '.join(column_names)}")
            
            # Show sample data if available
            if count > 0:
                sample = self.conn.execute(f"SELECT * FROM {table_name} LIMIT 3").fetchall()
                print(f"   Sample data:")
                for i, row in enumerate(sample, 1):
                    # Show first few columns to avoid overwhelming output
                    sample_data = dict(row)
                    # Truncate long JSON fields
                    for key, value in sample_data.items():
                        if isinstance(value, str) and len(value) > 100:
                            sample_data[key] = value[:100] + "..."
                    
                    print(f"     {i}. {sample_data}")
    
    def analyze_scenarios(self):
        """Analyze the scenarios table"""
        
        print("\n🎯 SCENARIOS ANALYSIS")
        print("=" * 50)
        
        try:
            # Basic stats
            total_scenarios = self.conn.execute("SELECT COUNT(*) FROM scenarios").fetchone()[0]
            print(f"📊 Total Scenarios: {total_scenarios:,}")
            
            # Environment distribution
            env_stats = self.conn.execute("""
                SELECT environment_type, COUNT(*) as count
                FROM scenarios
                WHERE environment_type IS NOT NULL
                GROUP BY environment_type
                ORDER BY count DESC
            """).fetchall()
            
            print(f"\n🌍 Environment Distribution:")
            for env in env_stats:
                percentage = (env['count'] / total_scenarios) * 100
                print(f"   {env['environment_type']}: {env['count']} ({percentage:.1f}%)")
            
            # OS Family distribution
            os_stats = self.conn.execute("""
                SELECT os_family, COUNT(*) as count
                FROM scenarios
                WHERE os_family IS NOT NULL
                GROUP BY os_family
                ORDER BY count DESC
            """).fetchall()
            
            print(f"\n💻 OS Family Distribution:")
            for os in os_stats:
                percentage = (os['count'] / total_scenarios) * 100
                print(f"   {os['os_family']}: {os['count']} ({percentage:.1f}%)")
            
            # Complexity distribution
            complexity_stats = self.conn.execute("""
                SELECT attack_complexity, COUNT(*) as count
                FROM scenarios
                WHERE attack_complexity IS NOT NULL
                GROUP BY attack_complexity
                ORDER BY count DESC
            """).fetchall()
            
            print(f"\n⚡ Attack Complexity Distribution:")
            for complexity in complexity_stats:
                percentage = (complexity['count'] / total_scenarios) * 100
                print(f"   {complexity['attack_complexity']}: {complexity['count']} ({percentage:.1f}%)")
            
            # Canonical groupings
            canonical_stats = self.conn.execute("""
                SELECT canonical_name, COUNT(*) as count
                FROM scenarios
                WHERE canonical_name IS NOT NULL
                GROUP BY canonical_name
                ORDER BY count DESC
                LIMIT 15
            """).fetchall()
            
            print(f"\n📚 Top Canonical Scenario Groups:")
            for canonical in canonical_stats:
                print(f"   {canonical['canonical_name']}: {canonical['count']} scenarios")
            
            # Port signature analysis
            print(f"\n🔌 Port Signature Analysis:")
            port_scenarios = self.conn.execute("""
                SELECT port_signature, COUNT(*) as count
                FROM scenarios
                WHERE port_signature IS NOT NULL AND port_signature != ''
                GROUP BY port_signature
                ORDER BY count DESC
                LIMIT 10
            """).fetchall()
            
            for port_sig in port_scenarios:
                print(f"   {port_sig['port_signature']}: {port_sig['count']} scenarios")
                
        except Exception as e:
            print(f"❌ Error analyzing scenarios: {e}")
    
    def analyze_techniques(self):
        """Analyze the techniques table"""
        
        print("\n🔧 TECHNIQUES ANALYSIS")
        print("=" * 50)
        
        try:
            # Basic stats
            total_techniques = self.conn.execute("SELECT COUNT(*) FROM techniques").fetchone()[0]
            print(f"📊 Total Techniques: {total_techniques:,}")
            
            # Most common techniques
            technique_stats = self.conn.execute("""
                SELECT name, COUNT(*) as count, AVG(success_rate) as avg_success_rate
                FROM techniques
                WHERE name IS NOT NULL
                GROUP BY name
                ORDER BY count DESC
                LIMIT 15
            """).fetchall()
            
            print(f"\n🎯 Most Common Techniques:")
            for tech in technique_stats:
                success_rate = tech['avg_success_rate'] or 0
                print(f"   {tech['name']}: {tech['count']} uses ({success_rate:.1%} avg success)")
            
            # Difficulty distribution
            difficulty_stats = self.conn.execute("""
                SELECT difficulty, COUNT(*) as count
                FROM techniques
                WHERE difficulty IS NOT NULL
                GROUP BY difficulty
                ORDER BY count DESC
            """).fetchall()
            
            print(f"\n⚡ Difficulty Distribution:")
            for diff in difficulty_stats:
                percentage = (diff['count'] / total_techniques) * 100
                print(f"   {diff['difficulty']}: {diff['count']} ({percentage:.1f}%)")
            
            # Category distribution
            category_stats = self.conn.execute("""
                SELECT category, COUNT(*) as count
                FROM techniques
                WHERE category IS NOT NULL AND category != ''
                GROUP BY category
                ORDER BY count DESC
            """).fetchall()
            
            print(f"\n📂 Category Distribution:")
            for cat in category_stats:
                percentage = (cat['count'] / total_techniques) * 100
                print(f"   {cat['category']}: {cat['count']} ({percentage:.1f}%)")
            
            # Success rate analysis
            success_stats = self.conn.execute("""
                SELECT 
                    AVG(success_rate) as avg_success_rate,
                    MIN(success_rate) as min_success_rate,
                    MAX(success_rate) as max_success_rate,
                    COUNT(CASE WHEN success_rate > 0.8 THEN 1 END) as high_success_count,
                    COUNT(CASE WHEN success_rate < 0.3 THEN 1 END) as low_success_count
                FROM techniques
                WHERE success_rate IS NOT NULL
            """).fetchone()
            
            print(f"\n📈 Success Rate Analysis:")
            print(f"   Average: {(success_stats['avg_success_rate'] or 0):.1%}")
            print(f"   Range: {(success_stats['min_success_rate'] or 0):.1%} - {(success_stats['max_success_rate'] or 0):.1%}")
            print(f"   High success (>80%): {success_stats['high_success_count']}")
            print(f"   Low success (<30%): {success_stats['low_success_count']}")
            
        except Exception as e:
            print(f"❌ Error analyzing techniques: {e}")
    
    def analyze_port_mappings(self):
        """Analyze port mappings"""
        
        print("\n🔌 PORT MAPPINGS ANALYSIS")
        print("=" * 50)
        
        try:
            # Basic stats
            total_mappings = self.conn.execute("SELECT COUNT(*) FROM port_mappings").fetchone()[0]
            unique_ports = self.conn.execute("SELECT COUNT(DISTINCT port) FROM port_mappings").fetchone()[0]
            
            print(f"📊 Total Port Mappings: {total_mappings:,}")
            print(f"🔢 Unique Ports: {unique_ports}")
            
            # Most common ports
            port_stats = self.conn.execute("""
                SELECT port, COUNT(*) as scenario_count, AVG(weight) as avg_weight
                FROM port_mappings
                GROUP BY port
                ORDER BY scenario_count DESC
                LIMIT 20
            """).fetchall()
            
            print(f"\n🎯 Most Common Ports:")
            for port in port_stats:
                print(f"   Port {port['port']}: {port['scenario_count']} scenarios (avg weight: {port['avg_weight']:.2f})")
            
            # Port weight distribution
            weight_stats = self.conn.execute("""
                SELECT 
                    AVG(weight) as avg_weight,
                    MIN(weight) as min_weight,
                    MAX(weight) as max_weight,
                    COUNT(CASE WHEN weight > 0.8 THEN 1 END) as high_weight_count,
                    COUNT(CASE WHEN weight < 0.2 THEN 1 END) as low_weight_count
                FROM port_mappings
                WHERE weight IS NOT NULL
            """).fetchone()
            
            print(f"\n⚖️ Weight Distribution:")
            print(f"   Average: {weight_stats['avg_weight']:.2f}")
            print(f"   Range: {weight_stats['min_weight']:.2f} - {weight_stats['max_weight']:.2f}")
            print(f"   High weight (>0.8): {weight_stats['high_weight_count']}")
            print(f"   Low weight (<0.2): {weight_stats['low_weight_count']}")
            
        except Exception as e:
            print(f"❌ Error analyzing port mappings: {e}")
    
    def analyze_service_mappings(self):
        """Analyze service mappings"""
        
        print("\n🔧 SERVICE MAPPINGS ANALYSIS")
        print("=" * 50)
        
        try:
            # Basic stats
            total_mappings = self.conn.execute("SELECT COUNT(*) FROM service_mappings").fetchone()[0]
            unique_services = self.conn.execute("SELECT COUNT(DISTINCT service_name) FROM service_mappings").fetchone()[0]
            
            print(f"📊 Total Service Mappings: {total_mappings:,}")
            print(f"🔢 Unique Services: {unique_services}")
            
            # Most common services
            service_stats = self.conn.execute("""
                SELECT service_name, COUNT(*) as scenario_count, AVG(weight) as avg_weight
                FROM service_mappings
                GROUP BY service_name
                ORDER BY scenario_count DESC
                LIMIT 20
            """).fetchall()
            
            print(f"\n🎯 Most Common Services:")
            for service in service_stats:
                print(f"   {service['service_name']}: {service['scenario_count']} scenarios (avg weight: {service['avg_weight']:.2f})")
            
        except Exception as e:
            print(f"❌ Error analyzing service mappings: {e}")
    
    def find_hardcoded_values_to_replace(self):
        """Find specific data that can replace hardcoded values in intelligence_matcher.py"""
        
        print("\n🔄 HARDCODED VALUES REPLACEMENT ANALYSIS")
        print("=" * 50)
        
        try:
            # Find SMB-related techniques
            smb_techniques = self.conn.execute("""
                SELECT DISTINCT t.name, t.success_rate, t.difficulty, t.data_json
                FROM techniques t
                JOIN scenarios s ON t.scenario_id = s.id
                JOIN port_mappings pm ON pm.scenario_id = s.id
                WHERE pm.port IN (445, 139) OR s.service_combination LIKE '%smb%'
                ORDER BY t.success_rate DESC
                LIMIT 10
            """).fetchall()
            
            print(f"🔍 SMB-related techniques (replaces hardcoded SMB enumeration):")
            for tech in smb_techniques:
                print(f"   {tech['name']}: {tech['success_rate']:.1%} ({tech['difficulty']})")
            
            # Find web-related techniques
            web_techniques = self.conn.execute("""
                SELECT DISTINCT t.name, t.success_rate, t.difficulty, t.data_json
                FROM techniques t
                JOIN scenarios s ON t.scenario_id = s.id
                JOIN port_mappings pm ON pm.scenario_id = s.id
                WHERE pm.port IN (80, 443, 8080, 8443) OR s.service_combination LIKE '%http%'
                ORDER BY t.success_rate DESC
                LIMIT 10
            """).fetchall()
            
            print(f"\n🌐 Web-related techniques (replaces hardcoded web enumeration):")
            for tech in web_techniques:
                print(f"   {tech['name']}: {tech['success_rate']:.1%} ({tech['difficulty']})")
            
            # Find SSH-related techniques
            ssh_techniques = self.conn.execute("""
                SELECT DISTINCT t.name, t.success_rate, t.difficulty, t.data_json
                FROM techniques t
                JOIN scenarios s ON t.scenario_id = s.id
                JOIN port_mappings pm ON pm.scenario_id = s.id
                WHERE pm.port = 22 OR s.service_combination LIKE '%ssh%'
                ORDER BY t.success_rate DESC
                LIMIT 10
            """).fetchall()
            
            print(f"\n🔑 SSH-related techniques (replaces hardcoded SSH analysis):")
            for tech in ssh_techniques:
                print(f"   {tech['name']}: {tech['success_rate']:.1%} ({tech['difficulty']})")
            
            # Find Active Directory techniques
            ad_techniques = self.conn.execute("""
                SELECT DISTINCT t.name, t.success_rate, t.difficulty, t.data_json
                FROM techniques t
                JOIN scenarios s ON t.scenario_id = s.id
                WHERE s.environment_type = 'active_directory' OR s.canonical_name LIKE '%active_directory%'
                ORDER BY t.success_rate DESC
                LIMIT 10
            """).fetchall()
            
            print(f"\n🏢 Active Directory techniques (replaces hardcoded AD recommendations):")
            for tech in ad_techniques:
                print(f"   {tech['name']}: {tech['success_rate']:.1%} ({tech['difficulty']})")
            
            # Find database-related techniques
            db_techniques = self.conn.execute("""
                SELECT DISTINCT t.name, t.success_rate, t.difficulty, t.data_json
                FROM techniques t
                JOIN scenarios s ON t.scenario_id = s.id
                JOIN port_mappings pm ON pm.scenario_id = s.id
                WHERE pm.port IN (3306, 5432, 1433, 27017) OR s.environment_type = 'database_server'
                ORDER BY t.success_rate DESC
                LIMIT 10
            """).fetchall()
            
            print(f"\n🗄️ Database-related techniques (replaces hardcoded DB enumeration):")
            for tech in db_techniques:
                print(f"   {tech['name']}: {tech['success_rate']:.1%} ({tech['difficulty']})")
            
        except Exception as e:
            print(f"❌ Error finding replacement values: {e}")
    
    def export_technique_data(self, output_file: str = "technique_export.json"):
        """Export technique data for use in enhanced matcher"""
        
        print(f"\n📤 EXPORTING TECHNIQUE DATA")
        print("=" * 50)
        
        try:
            # Export all techniques with their metadata
            techniques = self.conn.execute("""
                SELECT 
                    t.name, t.success_rate, t.difficulty, t.time_estimate,
                    t.category, t.mitre_id, t.data_json,
                    s.environment_type, s.os_family, s.attack_complexity,
                    GROUP_CONCAT(DISTINCT pm.port) as ports,
                    GROUP_CONCAT(DISTINCT sm.service_name) as services
                FROM techniques t
                JOIN scenarios s ON t.scenario_id = s.id
                LEFT JOIN port_mappings pm ON pm.scenario_id = s.id
                LEFT JOIN service_mappings sm ON sm.scenario_id = s.id
                GROUP BY t.name, t.success_rate, t.difficulty, t.time_estimate,
                         t.category, t.mitre_id, t.data_json,
                         s.environment_type, s.os_family, s.attack_complexity
            """).fetchall()
            
            export_data = []
            for tech in techniques:
                tech_data = {
                    'name': tech['name'],
                    'success_rate': tech['success_rate'],
                    'difficulty': tech['difficulty'],
                    'time_estimate': tech['time_estimate'],
                    'category': tech['category'],
                    'mitre_id': tech['mitre_id'],
                    'environment_type': tech['environment_type'],
                    'os_family': tech['os_family'],
                    'attack_complexity': tech['attack_complexity'],
                    'associated_ports': tech['ports'].split(',') if tech['ports'] else [],
                    'associated_services': tech['services'].split(',') if tech['services'] else []
                }
                
                # Parse JSON data if available
                if tech['data_json']:
                    try:
                        json_data = json.loads(tech['data_json'])
                        tech_data['tools'] = json_data.get('tools', [])
                        tech_data['commands'] = json_data.get('commands', [])
                        tech_data['description'] = json_data.get('description', '')
                    except json.JSONDecodeError:
                        pass
                
                export_data.append(tech_data)
            
            # Save to file
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            print(f"✅ Exported {len(export_data)} techniques to {output_file}")
            
        except Exception as e:
            print(f"❌ Error exporting technique data: {e}")
    
    def generate_summary_report(self):
        """Generate a comprehensive summary report"""
        
        print("\n📋 COMPREHENSIVE SUMMARY REPORT")
        print("=" * 50)
        
        try:
            # Collect all statistics
            total_scenarios = self.conn.execute("SELECT COUNT(*) FROM scenarios").fetchone()[0]
            total_techniques = self.conn.execute("SELECT COUNT(*) FROM techniques").fetchone()[0]
            total_port_mappings = self.conn.execute("SELECT COUNT(*) FROM port_mappings").fetchone()[0]
            total_service_mappings = self.conn.execute("SELECT COUNT(*) FROM service_mappings").fetchone()[0]
            
            unique_ports = self.conn.execute("SELECT COUNT(DISTINCT port) FROM port_mappings").fetchone()[0]
            unique_services = self.conn.execute("SELECT COUNT(DISTINCT service_name) FROM service_mappings").fetchone()[0]
            unique_environments = self.conn.execute("SELECT COUNT(DISTINCT environment_type) FROM scenarios WHERE environment_type IS NOT NULL").fetchone()[0]
            
            print(f"📊 DATABASE OVERVIEW:")
            print(f"   Total Scenarios: {total_scenarios:,}")
            print(f"   Total Techniques: {total_techniques:,}")
            print(f"   Port Mappings: {total_port_mappings:,}")
            print(f"   Service Mappings: {total_service_mappings:,}")
            print(f"   Unique Ports Covered: {unique_ports}")
            print(f"   Unique Services Covered: {unique_services}")
            print(f"   Environment Types: {unique_environments}")
            
            # Data quality assessment
            scenarios_with_techniques = self.conn.execute("""
                SELECT COUNT(DISTINCT s.id) 
                FROM scenarios s
                JOIN techniques t ON t.scenario_id = s.id
            """).fetchone()[0]
            
            scenarios_with_ports = self.conn.execute("""
                SELECT COUNT(DISTINCT s.id)
                FROM scenarios s
                JOIN port_mappings pm ON pm.scenario_id = s.id
            """).fetchone()[0]
            
            print(f"\n🔍 DATA QUALITY:")
            print(f"   Scenarios with techniques: {scenarios_with_techniques}/{total_scenarios} ({scenarios_with_techniques/total_scenarios*100:.1f}%)")
            print(f"   Scenarios with port mappings: {scenarios_with_ports}/{total_scenarios} ({scenarios_with_ports/total_scenarios*100:.1f}%)")
            
            # Readiness assessment
            print(f"\n✅ READINESS FOR ENHANCED MATCHER:")
            readiness_score = 0
            
            if total_scenarios > 100:
                print(f"   ✅ Sufficient scenarios ({total_scenarios})")
                readiness_score += 1
            else:
                print(f"   ⚠️ Low scenario count ({total_scenarios})")
            
            if total_techniques > 500:
                print(f"   ✅ Rich technique database ({total_techniques})")
                readiness_score += 1
            else:
                print(f"   ⚠️ Limited technique coverage ({total_techniques})")
            
            if unique_ports > 50:
                print(f"   ✅ Good port coverage ({unique_ports})")
                readiness_score += 1
            else:
                print(f"   ⚠️ Limited port coverage ({unique_ports})")
            
            if unique_services > 30:
                print(f"   ✅ Good service coverage ({unique_services})")
                readiness_score += 1
            else:
                print(f"   ⚠️ Limited service coverage ({unique_services})")
            
            print(f"\n🎯 READINESS SCORE: {readiness_score}/4")
            
            if readiness_score >= 3:
                print("   🎉 Database is ready for enhanced matcher integration!")
            else:
                print("   ⚠️ Consider improving data coverage before integration")
                
        except Exception as e:
            print(f"❌ Error generating summary: {e}")
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


def main():
    """Main inspection function"""
    
    if len(sys.argv) < 2:
        print("Usage: python db_inspector.py <path_to_intelligence.db>")
        sys.exit(1)
    
    db_path = sys.argv[1]
    
    try:
        inspector = IntelligenceDatabaseInspector(db_path)
        
        # Run all analyses
        inspector.inspect_database_structure()
        inspector.analyze_scenarios()
        inspector.analyze_techniques()
        inspector.analyze_port_mappings()
        inspector.analyze_service_mappings()
        inspector.find_hardcoded_values_to_replace()
        inspector.generate_summary_report()
        
        # Export technique data
        inspector.export_technique_data()
        
        inspector.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()