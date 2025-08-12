import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set
from collections import defaultdict
import anthropic

class ScenarioMapper:
    """Maps scattered scenario names to canonical categories while preserving writeup connections"""
    
    def __init__(self, anthropic_api_key: str):
        self.anthropic_client = anthropic.Anthropic(api_key=anthropic_api_key)
        self.scenario_mapping = {}
        self.canonical_groups = {}
        self.writeup_mappings = {}
        
    def extract_all_scenarios(self, intelligence_dir: str) -> Dict[str, List[str]]:
        """Extract all scenario names and their corresponding writeups"""
        
        intelligence_path = Path(intelligence_dir)
        scenario_to_writeups = defaultdict(list)
        
        print("🔍 Scanning all intelligence files for scenario names...")
        
        for intel_file in intelligence_path.glob("*.json"):
            try:
                with open(intel_file, 'r') as f:
                    data = json.load(f)
                
                scenario = data.get('scenario_fingerprint', {})
                scenario_name = scenario.get('scenario_name', 'unknown')
                
                if scenario_name and scenario_name != 'unknown':
                    writeup_id = data.get('writeup_id', intel_file.stem)
                    scenario_to_writeups[scenario_name].append(writeup_id)
                    
            except Exception as e:
                print(f"⚠️ Error reading {intel_file}: {e}")
        
        print(f"📊 Found {len(scenario_to_writeups)} unique scenario names")
        print(f"📝 Most common scenarios:")
        
        # Show top scenarios
        sorted_scenarios = sorted(scenario_to_writeups.items(), key=lambda x: len(x[1]), reverse=True)
        for scenario, writeups in sorted_scenarios[:10]:
            print(f"   {len(writeups):2d}x {scenario}")
        
        return dict(scenario_to_writeups)
    
    def create_intelligent_grouping(self, scenario_data: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Use Claude to intelligently group similar scenario names"""
        
        scenario_names = list(scenario_data.keys())
        
        print(f"\n🧠 Using Claude to analyze {len(scenario_names)} scenario names...")
        print(f"💰 Estimated cost: $3-4 for intelligent grouping")
        
        # Prepare scenarios for Claude analysis
        scenarios_text = "\n".join([f"- {name} ({len(scenario_data[name])} writeups)" 
                                   for name in scenario_names])
        
        prompt = f"""
        You are analyzing penetration testing scenario names to create canonical groupings.
        These scenario names were auto-generated and need to be grouped into consistent categories.

        Your task: Group similar scenarios under canonical category names.
        Focus on the PRIMARY attack method/environment, not minor variations.

        CRITICAL RULES:
        1. Create exactly 15-20 canonical category names (no more!)
        2. Group aggressively - merge similar attack types
        3. Use format: primary_target_attack_method (e.g., "active_directory_authentication_attacks")
        4. Prioritize attack vector over specific tools/techniques
        5. Merge all SQL injection variants into one group
        6. Merge all Active Directory variants into 2-3 groups max
        7. Merge all web application attacks by primary method (SQLi, XSS, SSRF, etc.)

        EXAMPLE GROUPINGS (follow this pattern):
        - All AD/Kerberos → "active_directory_authentication_attacks"  
        - All SQL injection → "web_application_sql_injection"
        - All SSRF variants → "web_application_ssrf_attacks"
        - All privilege escalation → "linux_privilege_escalation" or "windows_privilege_escalation"
        - All container escapes → "container_escape_attacks"
        - All CMS attacks → "cms_exploitation_attacks"

        Return ONLY valid JSON in this format:
        {{
          "canonical_groups": {{
            "active_directory_authentication_attacks": [
              "windows_domain_controller_asreproast_complex",
              "windows_domain_controller_advanced_ad_exploitation", 
              "windows_domain_controller_bloodhound_privilege_escalation",
              "windows_domain_controller_xmpp_asreproast",
              "windows_domain_ntlm_disabled_kerberoast",
              "windows_asrep_roasting_attack"
            ],
            "web_application_sql_injection": [
              "linux_web_sqli_hash_extension_snmp_bof",
              "linux_web_sqli_preg_replace_cron_escalation", 
              "linux_web_sqli_file_read_privilege_escalation",
              "linux_web_sqli_to_docker_escape",
              "laravel_password_reset_bypass_sqli",
              "wordpress_bookingpress_sqli_to_xxe"
            ],
            "web_application_server_side_template_injection": [
              "linux_ruby_ssti_webapp",
              "linux_web_ssti_ocr_privilege_escalation",
              "golang_web_ssti_aws_privilege_escalation"
            ]
          }},
          "grouping_rationale": {{
            "active_directory_authentication_attacks": "All scenarios involving Kerberos, AS-REP roasting, and AD authentication bypass attacks",
            "web_application_sql_injection": "All web applications vulnerable to SQL injection regardless of specific database or exploitation chain",
            "web_application_server_side_template_injection": "All SSTI attacks against web applications regardless of template engine"
          }}
        }}

        BE AGGRESSIVE in grouping - aim for 15-20 groups total, not 200+!
        
        Current scattered scenario names ({len(scenario_names)} total):
        {scenarios_text}
        """
        
        try:
            response = self.anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}]
            )
            
            content = response.content[0].text.strip()
            
            # Parse the JSON response
            if content.startswith('```json'):
                content = content.replace('```json', '').replace('```', '').strip()
            
            grouping_data = json.loads(content)
            canonical_groups = grouping_data.get('canonical_groups', {})
            rationale = grouping_data.get('grouping_rationale', {})
            
            print(f"✅ Claude created {len(canonical_groups)} canonical groups")
            
            # Show the groupings
            print(f"\n📋 CANONICAL GROUPINGS:")
            for canonical_name, scenarios in canonical_groups.items():
                total_writeups = sum(len(scenario_data.get(scenario, [])) for scenario in scenarios)
                print(f"\n🎯 {canonical_name} ({total_writeups} writeups total)")
                print(f"   📝 {rationale.get(canonical_name, 'No rationale provided')}")
                for scenario in scenarios[:3]:  # Show first 3
                    count = len(scenario_data.get(scenario, []))
                    print(f"     • {scenario} ({count} writeups)")
                if len(scenarios) > 3:
                    print(f"     ... and {len(scenarios) - 3} more scenarios")
            
            return canonical_groups
            
        except Exception as e:
            print(f"❌ Claude grouping failed: {e}")
            print("🔄 Falling back to rule-based grouping...")
            return self._fallback_rule_based_grouping(scenario_names)
    
    def _fallback_rule_based_grouping(self, scenario_names: List[str]) -> Dict[str, List[str]]:
        """Fallback rule-based grouping if Claude fails - much more aggressive"""
        
        groups = defaultdict(list)
        
        for scenario in scenario_names:
            scenario_lower = scenario.lower()
            
            # Active Directory attacks
            if any(kw in scenario_lower for kw in ['asrep', 'kerberos', 'domain_controller', 'active_directory', 'bloodhound', 'gmsa', 'ldap_injection']):
                groups['active_directory_authentication_attacks'].append(scenario)
            
            # SQL Injection attacks
            elif any(kw in scenario_lower for kw in ['sqli', 'sql_injection', 'sql_truncation']):
                groups['web_application_sql_injection'].append(scenario)
            
            # SSRF attacks
            elif 'ssrf' in scenario_lower:
                groups['web_application_ssrf_attacks'].append(scenario)
            
            # XSS attacks
            elif 'xss' in scenario_lower:
                groups['web_application_xss_attacks'].append(scenario)
            
            # Template injection
            elif 'ssti' in scenario_lower or 'template' in scenario_lower:
                groups['web_application_template_injection'].append(scenario)
            
            # Deserialization attacks
            elif any(kw in scenario_lower for kw in ['deserialization', 'deserialize', 'pickle']):
                groups['deserialization_attacks'].append(scenario)
            
            # Container/Docker attacks
            elif any(kw in scenario_lower for kw in ['docker', 'container', 'kubernetes', 'escape']):
                groups['container_escape_attacks'].append(scenario)
            
            # CMS attacks
            elif any(kw in scenario_lower for kw in ['wordpress', 'drupal', 'joomla', 'cms', 'moodle']):
                groups['cms_exploitation_attacks'].append(scenario)
            
            # File upload attacks
            elif any(kw in scenario_lower for kw in ['file_upload', 'upload', 'webshell']):
                groups['web_application_file_upload'].append(scenario)
            
            # Privilege escalation (Linux)
            elif 'linux' in scenario_lower and any(kw in scenario_lower for kw in ['privilege_escalation', 'privesc', 'escalation']):
                groups['linux_privilege_escalation'].append(scenario)
            
            # Privilege escalation (Windows)
            elif 'windows' in scenario_lower and any(kw in scenario_lower for kw in ['privilege_escalation', 'privesc', 'escalation']):
                groups['windows_privilege_escalation'].append(scenario)
            
            # Windows exploitation (general)
            elif 'windows' in scenario_lower and not any(kw in scenario_lower for kw in ['domain_controller', 'active_directory']):
                groups['windows_exploitation'].append(scenario)
            
            # Web application vulnerabilities (general)
            elif any(kw in scenario_lower for kw in ['web_app', 'web_application', 'flask', 'nodejs', 'laravel']):
                groups['web_application_vulnerabilities'].append(scenario)
            
            # Linux web services
            elif 'linux' in scenario_lower and 'web' in scenario_lower:
                groups['linux_web_service_exploitation'].append(scenario)
            
            # API attacks
            elif 'api' in scenario_lower:
                groups['api_exploitation'].append(scenario)
            
            # Database attacks
            elif any(kw in scenario_lower for kw in ['mysql', 'mssql', 'database', 'sql']):
                groups['database_exploitation'].append(scenario)
            
            # Network service attacks
            elif any(kw in scenario_lower for kw in ['ftp', 'ssh', 'smtp', 'snmp', 'smb']):
                groups['network_service_exploitation'].append(scenario)
            
            # Cryptographic attacks
            elif any(kw in scenario_lower for kw in ['crypto', 'hash', 'cipher', 'jwt']):
                groups['cryptographic_attacks'].append(scenario)
            
            # Everything else
            else:
                groups['miscellaneous_attacks'].append(scenario)
        
        print(f"🔄 Created {len(groups)} aggressive rule-based groups")
        return dict(groups)
    
    def create_reverse_mapping(self, canonical_groups: Dict[str, List[str]], scenario_data: Dict[str, List[str]]) -> Dict[str, str]:
        """Create reverse mapping from original scenario to canonical name"""
        
        reverse_mapping = {}
        
        for canonical_name, scenarios in canonical_groups.items():
            for scenario in scenarios:
                reverse_mapping[scenario] = canonical_name
        
        # Handle unmapped scenarios
        all_original_scenarios = set(scenario_data.keys())
        mapped_scenarios = set(reverse_mapping.keys())
        unmapped = all_original_scenarios - mapped_scenarios
        
        if unmapped:
            print(f"⚠️ {len(unmapped)} scenarios weren't mapped:")
            for scenario in list(unmapped)[:5]:
                print(f"   • {scenario}")
                reverse_mapping[scenario] = "uncategorized_attacks"
            if len(unmapped) > 5:
                print(f"   ... and {len(unmapped) - 5} more")
        
        return reverse_mapping
    
    def generate_updated_summary(self, intelligence_dir: str, output_dir: str, 
                                canonical_groups: Dict[str, List[str]], 
                                scenario_data: Dict[str, List[str]]) -> None:
        """Generate updated intelligence summary with canonical groupings"""
        
        output_path = Path(output_dir)
        
        # Calculate new scenario distribution
        canonical_distribution = {}
        canonical_writeup_details = {}
        
        for canonical_name, scenarios in canonical_groups.items():
            total_writeups = []
            for scenario in scenarios:
                writeups = scenario_data.get(scenario, [])
                total_writeups.extend(writeups)
            
            canonical_distribution[canonical_name] = len(total_writeups)
            canonical_writeup_details[canonical_name] = {
                "writeup_count": len(total_writeups),
                "original_scenarios": {scenario: len(scenario_data.get(scenario, [])) 
                                     for scenario in scenarios},
                "writeup_ids": total_writeups
            }
        
        # Sort by frequency
        canonical_distribution = dict(sorted(canonical_distribution.items(), 
                                           key=lambda x: x[1], reverse=True))
        
        # Create comprehensive mapping report
        mapping_report = {
            "mapping_metadata": {
                "creation_date": datetime.now().isoformat(),
                "original_scenario_count": len(scenario_data),
                "canonical_group_count": len(canonical_groups),
                "total_writeups_mapped": sum(len(writeups) for writeups in scenario_data.values()),
                "reduction_ratio": f"{len(scenario_data) / len(canonical_groups):.1f}:1"
            },
            "canonical_scenario_distribution": canonical_distribution,
            "detailed_mappings": canonical_writeup_details,
            "scenario_name_mapping": self.create_reverse_mapping(canonical_groups, scenario_data),
            "original_to_canonical_groups": canonical_groups
        }
        
        # Save mapping report
        with open(output_path / "scenario_mapping_report.json", 'w') as f:
            json.dump(mapping_report, f, indent=2)
        
        print(f"\n📊 UPDATED SCENARIO DISTRIBUTION:")
        print(f"{'Canonical Scenario':<40} {'Count':<8} {'Original Scenarios'}")
        print("-" * 70)
        
        for canonical_name, count in list(canonical_distribution.items())[:15]:
            original_count = len(canonical_groups[canonical_name])
            print(f"{canonical_name:<40} {count:<8} {original_count} scenarios")
        
        print(f"\n💾 Mapping report saved to: {output_path / 'scenario_mapping_report.json'}")
        print(f"📈 Reduced from {len(scenario_data)} to {len(canonical_groups)} scenario types")
        print(f"🎯 Compression ratio: {len(scenario_data) / len(canonical_groups):.1f}:1")
    
    def update_individual_intelligence_files(self, intelligence_dir: str, 
                                           reverse_mapping: Dict[str, str]) -> None:
        """Update individual intelligence files with canonical scenario names"""
        
        intelligence_path = Path(intelligence_dir)
        updated_count = 0
        
        print(f"\n🔄 Updating individual intelligence files...")
        
        for intel_file in intelligence_path.glob("*.json"):
            try:
                with open(intel_file, 'r') as f:
                    data = json.load(f)
                
                scenario = data.get('scenario_fingerprint', {})
                original_name = scenario.get('scenario_name')
                
                if original_name and original_name in reverse_mapping:
                    canonical_name = reverse_mapping[original_name]
                    
                    # Update the scenario name
                    data['scenario_fingerprint']['scenario_name'] = canonical_name
                    data['scenario_fingerprint']['original_scenario_name'] = original_name
                    
                    # Save updated file
                    with open(intel_file, 'w') as f:
                        json.dump(data, f, indent=2)
                    
                    updated_count += 1
                    
            except Exception as e:
                print(f"⚠️ Error updating {intel_file}: {e}")
        
        print(f"✅ Updated {updated_count} intelligence files with canonical names")

def main():
    """Main execution function"""
    
    print("🎯 Scenario Name Mapper & Grouping Tool")
    print("=" * 50)
    print("💡 Purpose: Clean up scattered scenario names into canonical groups")
    print("💰 Cost: ~$3-4 using your remaining Claude credits")
    print("🎯 Benefit: Proper scenario distribution and better intelligence")
    print()
    
    # Configuration
    anthropic_api_key = "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"  # SET YOUR API KEY
    intelligence_dir = "intelligence_db/intelligence"
    output_dir = "intelligence_db/metadata"
    
    if not anthropic_api_key:
        print("❌ Please set your Anthropic API key in the script")
        return
    
    # Check if directories exist
    if not Path(intelligence_dir).exists():
        print(f"❌ Intelligence directory not found: {intelligence_dir}")
        return
    
    # Create mapper
    mapper = ScenarioMapper(anthropic_api_key)
    
    # Step 1: Extract all scenario names
    scenario_data = mapper.extract_all_scenarios(intelligence_dir)
    
    if not scenario_data:
        print("❌ No scenario data found!")
        return
    
    # Show some statistics
    total_writeups = sum(len(writeups) for writeups in scenario_data.values())
    avg_per_scenario = total_writeups / len(scenario_data)
    
    print(f"\n📊 CURRENT SITUATION:")
    print(f"   Total scenarios: {len(scenario_data)}")
    print(f"   Total writeups: {total_writeups}")
    print(f"   Average per scenario: {avg_per_scenario:.1f}")
    print(f"   Scenarios with 1 writeup: {sum(1 for v in scenario_data.values() if len(v) == 1)}")
    
    if input("\nProceed with AI-powered grouping? (y/n): ").lower() != 'y':
        print("👋 Operation cancelled")
        return
    
    # Step 2: Create intelligent grouping
    canonical_groups = mapper.create_intelligent_grouping(scenario_data)
    
    if not canonical_groups:
        print("❌ Grouping failed!")
        return
    
    # Step 3: Create reverse mapping
    reverse_mapping = mapper.create_reverse_mapping(canonical_groups, scenario_data)
    
    # Step 4: Generate updated summary
    mapper.generate_updated_summary(intelligence_dir, output_dir, 
                                  canonical_groups, scenario_data)
    
    # Step 5: Ask if user wants to update individual files
    print(f"\n🔄 UPDATE OPTIONS:")
    print(f"1) Just create the mapping report (recommended first)")
    print(f"2) Also update all individual intelligence files")
    
    choice = input("Choose (1-2): ").strip()
    
    if choice == "2":
        mapper.update_individual_intelligence_files(intelligence_dir, reverse_mapping)
        print(f"✅ All files updated with canonical scenario names")
    
    print(f"\n🎉 SCENARIO MAPPING COMPLETE!")
    print(f"📁 Check: intelligence_db/metadata/scenario_mapping_report.json")
    print(f"📊 Your intelligence summary is now much cleaner!")
    print(f"💰 Cost: ~$3-4 (worth it for cleaning up your $80 investment)")

if __name__ == "__main__":
    main()