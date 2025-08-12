
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
