#!/usr/bin/env python3

"""
Intelligence Database Builder & Demo
Builds high-performance intelligence database from extracted writeup intelligence
"""

import sys
from pathlib import Path

# Import our intelligence modules
from intelligence_core import IntelligenceDatabase
from intelligence_matcher import IntelligenceMatcher, IntelligenceQuery
from intelligence_analytics import IntelligenceAnalytics, IntelligenceReporting

def main():
    """Main function to build and test the intelligence database"""
    
    print("🧠 Intelligence Database & Index Builder")
    print("=" * 50)
    print("Building high-performance intelligence database from your extractions...")
    print()
    
    # Configuration
    intelligence_dir = "intelligence_db/intelligence"
    mapping_file = "intelligence_db/metadata/scenario_mapping_report.json"
    
    # Check if directories exist
    if not Path(intelligence_dir).exists():
        print(f"❌ Intelligence directory not found: {intelligence_dir}")
        print("Run the intelligence extraction first!")
        return
    
    # Initialize database
    db = IntelligenceDatabase("intelligence_db")
    
    # Build database from intelligence files
    print("📊 Building database from intelligence extractions...")
    db.build_from_intelligence_files(intelligence_dir, mapping_file)
    
    # Initialize analytics and query systems
    analytics = IntelligenceAnalytics(db)
    reporting = IntelligenceReporting(analytics)
    query = IntelligenceQuery(db)
    
    print(f"\n🎯 Testing statistical analysis...")
    
    # Test comprehensive report
    comprehensive_report = analytics.generate_comprehensive_report()
    print(comprehensive_report)
    
    # Test specific scenario analysis
    print(f"\n📊 Testing scenario-specific success rates...")
    
    # Find a good scenario to test with
    canonical_stats = analytics.get_canonical_scenario_stats()
    if canonical_stats:
        test_scenario = canonical_stats[0]['canonical_name']
        print(f"🎯 Analyzing: {test_scenario}")
        
        # Generate success rate report
        success_report = analytics.generate_success_rate_report(test_scenario)
        print(f"\n{success_report}")
        
        # Generate full dashboard
        dashboard = reporting.generate_scenario_dashboard(test_scenario)
        print(f"\n{dashboard}")
    
    # Test comparison between scenarios
    if len(canonical_stats) >= 2:
        print(f"\n🔄 Testing scenario comparison...")
        comparison_scenarios = [s['canonical_name'] for s in canonical_stats[:3]]
        comparison_report = reporting.generate_comparative_analysis(comparison_scenarios)
        print(f"\n{comparison_report}")
    
    # Save all reports
    reports_dir = Path("intelligence_db/reports")
    reports_dir.mkdir(exist_ok=True)
    
    # Save comprehensive report
    with open(reports_dir / "comprehensive_analysis.txt", 'w') as f:
        f.write(comprehensive_report)
    
    # Save individual scenario reports
    for i, stat in enumerate(canonical_stats[:5]):  # Top 5 scenarios
        scenario_name = stat['canonical_name']
        dashboard = reporting.generate_scenario_dashboard(scenario_name)
        
        safe_filename = scenario_name.replace('/', '_').replace(' ', '_')
        with open(reports_dir / f"{safe_filename}_dashboard.txt", 'w') as f:
            f.write(dashboard)
    
    print(f"\n✅ Statistical analysis system ready!")
    print(f"📊 Features available:")
    print(f"   • Success rate analysis with confidence scoring")
    print(f"   • Visual progress bars and statistics")
    print(f"   • Environment-specific success rates") 
    print(f"   • Attack complexity analysis")
    print(f"   • Scenario comparison reports")
    print(f"   • Attack timeline estimation")
    print(f"📁 Reports saved to: {reports_dir}")
    
    # Test with example nmap output
    test_nmap = """
    22/tcp  open  ssh     OpenSSH 8.2p1
    53/tcp  open  domain  ISC BIND 9.16.1
    88/tcp  open  kerberos-sec Microsoft Windows Kerberos
    135/tcp open  msrpc   Microsoft Windows RPC
    389/tcp open  ldap    Microsoft Windows Active Directory LDAP
    445/tcp open  microsoft-ds Microsoft Windows Server 2019
    """
    
    print(f"\n🔍 Testing with Active Directory-like scan results...")
    matches = query.quick_match(test_nmap)
    
    print(f"\n📊 Found {len(matches)} scenario matches:")
    for i, match in enumerate(matches[:3], 1):
        print(f"{i}. {match.canonical_name}")
        print(f"   Confidence: {match.confidence:.2f}")
        print(f"   Factors: {', '.join(match.matching_factors)}")
        print(f"   Techniques: {', '.join(match.recommended_techniques[:2])}")
        print(f"   Time: {match.expected_time}")
        print()
    
    # Test attack recommendations
    if matches:
        print(f"🎯 Getting attack recommendations for top match...")
        recommendations = query.get_attack_recommendations(matches[0])
        
        print(f"📋 Attack Sequence Steps:")
        for i, step in enumerate(recommendations.get('attack_sequence', [])[:3], 1):
            if isinstance(step, dict):
                if 'steps' in step:
                    print(f"   {i}. {step.get('name', 'Unknown sequence')}")
                    for substep in step['steps'][:2]:
                        print(f"      → {substep.get('purpose', substep.get('command', 'Unknown'))}")
                else:
                    print(f"   {i}. {step.get('action', 'Unknown action')}")
        
        print(f"\n🔧 Required Tools:")
        for tool in recommendations.get('tools_required', [])[:3]:
            print(f"   • {tool['name']}: {tool.get('purpose', 'No description')}")
    
    print(f"\n✅ Intelligence database is ready!")
    print(f"📁 Database location: intelligence_db/intelligence.db")
    print(f"🚀 You can now integrate this with JASMIN for real-time intelligence!")
    
    # Save usage examples
    examples_file = Path("intelligence_db/metadata/usage_examples.py")
    usage_examples = '''
# Intelligence Database Usage Examples

from intelligence_core import IntelligenceDatabase
from intelligence_matcher import IntelligenceQuery
from intelligence_analytics import IntelligenceAnalytics, IntelligenceReporting

# Initialize the system
db = IntelligenceDatabase("intelligence_db")
query = IntelligenceQuery(db)
analytics = IntelligenceAnalytics(db)
reporting = IntelligenceReporting(analytics)

# 1. Quick scenario matching from nmap output
nmap_output = """
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
"""
matches = query.quick_match(nmap_output)
print(f"Found {len(matches)} matching scenarios")

# 2. Search by canonical scenario name
ad_scenarios = query.search_by_canonical("active_directory_authentication_attacks")
print(f"Found {len(ad_scenarios)} AD attack scenarios")

# 3. Get detailed attack recommendations
if matches:
    recommendations = query.get_attack_recommendations(matches[0])
    print(f"Attack sequence: {len(recommendations['attack_sequence'])} steps")
    print(f"Tools needed: {len(recommendations['tools_required'])}")

# 4. Generate success rate analysis
success_report = analytics.generate_success_rate_report("web_application_sql_injection")
print(success_report)

# 5. Generate scenario dashboard
dashboard = reporting.generate_scenario_dashboard("linux_privilege_escalation")
print(dashboard)

# 6. Compare multiple scenarios
comparison = reporting.generate_comparative_analysis([
    "active_directory_authentication_attacks",
    "web_application_sql_injection", 
    "linux_privilege_escalation"
])
print(comparison)

# 7. Manual port/service matching
from intelligence_matcher import IntelligenceMatcher
matcher = IntelligenceMatcher(db)
matches = matcher.match_scan_results(
    ports=[22, 80, 443, 3306], 
    services=['ssh', 'http', 'https', 'mysql'],
    os_detected='Linux Ubuntu'
)

# 8. Environment detection
environments = matcher.detect_environment([88, 389, 445], ['kerberos', 'ldap', 'smb'])
print(f"Detected environments: {environments}")

# 9. Get technique success rates with confidence
techniques = analytics.get_technique_success_rates("smb_enumeration_attacks")
for tech in techniques[:5]:
    print(f"{tech['technique']}: {tech['success_rate']*100:.1f}% (confidence: {tech['confidence']:.2f})")

# 10. Generate timeline report
timeline = reporting.generate_attack_timeline_report("web_application_sql_injection")
print(timeline)
'''
    
    with open(examples_file, 'w') as f:
        f.write(usage_examples)
    
    print(f"📝 Usage examples saved to: {examples_file}")

def demo_jarvis_integration():
    """Demo showing how to integrate with JASMIN"""
    
    print("\n🤖 JASMIN INTEGRATION EXAMPLE")
    print("=" * 40)
    
    # This would go in your JASMIN scans.py
    integration_code = '''
# Add to your JASMIN scans.py file:

from intelligence_core import IntelligenceDatabase
from intelligence_matcher import IntelligenceQuery

# Initialize intelligence system (do this once at startup)
try:
    intelligence_db = IntelligenceDatabase("intelligence_db")
    intelligence_query = IntelligenceQuery(intelligence_db)
    print("[+] Intelligence database loaded successfully!")
except Exception as e:
    print(f"[!] Could not load intelligence database: {e}")
    intelligence_query = None

def get_attack_intelligence(nmap_file_path):
    """Get attack intelligence from nmap scan results"""
    
    if not intelligence_query:
        return "Intelligence database not available"
    
    # Read nmap output
    with open(nmap_file_path, 'r') as f:
        nmap_output = f.read()
    
    # Get scenario matches
    matches = intelligence_query.quick_match(nmap_output)
    
    if not matches:
        return "No matching attack scenarios found"
    
    # Get detailed recommendations for top match
    top_match = matches[0]
    recommendations = intelligence_query.get_attack_recommendations(top_match)
    
    # Format intelligence report
    report = f"""
🧠 ATTACK INTELLIGENCE REPORT
{'='*50}

🎯 Detected Scenario: {top_match.canonical_name}
   Confidence: {top_match.confidence:.2f}
   Expected Time: {top_match.expected_time}
   Matching Factors: {', '.join(top_match.matching_factors)}

🔧 Recommended Techniques:
"""
    
    for i, technique in enumerate(top_match.recommended_techniques[:5], 1):
        report += f"   {i}. {technique}\\n"
    
    report += f"""
📋 Attack Sequence:
"""
    
    for i, step in enumerate(recommendations.get('attack_sequence', [])[:3], 1):
        if isinstance(step, dict):
            name = step.get('name', step.get('action', 'Unknown step'))
            report += f"   {i}. {name}\\n"
    
    report += f"""
⚠️ Success Indicators to Watch For:
"""
    
    for indicator in recommendations.get('success_indicators', [])[:5]:
        report += f"   • {indicator}\\n"
    
    return report

# Modify your run_tcp_scan function to include intelligence:
def run_tcp_scan_with_intelligence(ip, boxname, outdir, logfile):
    # ... existing TCP scan code ...
    
    # After scan completes, get intelligence
    tcp_output_file = outdir / f"{boxname}.tcp_scan.txt"
    if tcp_output_file.exists():
        intelligence_report = get_attack_intelligence(tcp_output_file)
        
        # Save intelligence report
        intel_file = outdir / f"{boxname}_intelligence.txt"
        intel_file.write_text(intelligence_report)
        
        print(f"[+] Attack intelligence saved to {intel_file}")
        print("\\n" + intelligence_report)
'''
    
    print("📝 JASMIN Integration Code:")
    print(integration_code)
    
    print("\n💡 Integration Benefits:")
    print("   • Automatic scenario detection from nmap scans")
    print("   • Success rate predictions based on 500+ writeups")
    print("   • Recommended attack sequences")
    print("   • Time estimates for each phase")
    print("   • Success indicators to watch for")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        demo_jarvis_integration()
    else:
        main()