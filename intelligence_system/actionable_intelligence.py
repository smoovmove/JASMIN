#!/usr/bin/env python3

"""
Actionable Intelligence Reporting
Convert statistical data into clear pentester guidance
"""

from typing import Dict, List
from intelligence_analytics import IntelligenceAnalytics

class ActionableIntelligence:
    """Convert stats into clear pentester actions"""
    
    def __init__(self, analytics: IntelligenceAnalytics):
        self.analytics = analytics
    
    def generate_pentester_guidance(self, canonical_scenario: str) -> str:
        """Generate clear, actionable guidance based on pentesting workflow"""
        
        techniques = self.analytics.get_technique_success_rates(canonical_scenario)
        if not techniques:
            return f"No technique data available for {canonical_scenario}"
        
        # Categorize by pentesting workflow, not just statistics
        core_recon = []      # Always do first - foundational
        quick_wins = []      # 30-second checks - "why not try"
        targeted_attacks = []# Specific exploits based on findings
        post_foothold = []   # After you have access
        
        for tech in techniques:
            tech_name = tech['technique'].lower()
            success_rate = tech['success_rate']
            confidence = tech['confidence']
            usage_count = tech['usage_count']
            
            # Core reconnaissance (always do these first)
            if any(word in tech_name for word in [
                'directory enumeration', 'web enumeration', 'service enumeration',
                'port scan', 'version detection', 'subdomain', 'dns enumeration',
                'certificate', 'technology detection'
            ]):
                core_recon.append(tech)
            
            # Quick wins (fast checks - low effort, low expectation)
            elif any(word in tech_name for word in [
                'anonymous', 'default credential', 'null session', 'guest access',
                'public', 'unauthenticated', 'banner grab'
            ]):
                quick_wins.append(tech)
            
            # Post-foothold activities
            elif any(word in tech_name for word in [
                'privilege escalation', 'lateral movement', 'persistence',
                'credential dump', 'hash extract', 'memory dump'
            ]):
                post_foothold.append(tech)
            
            # Everything else is targeted attacks
            else:
                targeted_attacks.append(tech)
        
        # Sort each category by practical value (mix of success rate and confidence)
        def practical_score(tech):
            base_score = tech['success_rate'] * 100
            # Boost techniques with more examples
            confidence_boost = min(10, tech['usage_count'] * 2)
            return base_score + confidence_boost
        
        core_recon.sort(key=practical_score, reverse=True)
        quick_wins.sort(key=practical_score, reverse=True)
        targeted_attacks.sort(key=practical_score, reverse=True)
        post_foothold.sort(key=practical_score, reverse=True)
        
        # Generate pentesting workflow report
        report_lines = []
        scenario_display = canonical_scenario.replace('_', ' ').title()
        
        report_lines.append(f"PENTESTING WORKFLOW - {scenario_display.upper()}")
        report_lines.append("=" * 70)
        report_lines.append("")
        
        # Phase 1: Core Reconnaissance
        if core_recon:
            report_lines.append("PHASE 1: CORE RECONNAISSANCE (Start here)")
            report_lines.append("   Do these first - they reveal your attack surface")
            for i, tech in enumerate(core_recon[:4], 1):
                name = tech['technique'][:55]
                rate = tech['success_rate'] * 100
                examples = tech['usage_count']
                report_lines.append(f"   {i}. {name:<55} {rate:>5.0f}% ({examples}x)")
            report_lines.append("")
        
        # Phase 2: Quick Wins
        if quick_wins:
            report_lines.append("PHASE 2: QUICK WINS (30 seconds each)")
            report_lines.append("   Fast checks - low effort, sometimes pay off big")
            for i, tech in enumerate(quick_wins[:4], 1):
                name = tech['technique'][:55]
                rate = tech['success_rate'] * 100
                examples = tech['usage_count']
                report_lines.append(f"   {i}. {name:<55} {rate:>5.0f}% ({examples}x)")
            report_lines.append("")
        
        # Phase 3: Targeted Attacks
        if targeted_attacks:
            report_lines.append("PHASE 3: TARGETED ATTACKS (Based on findings)")
            report_lines.append("   Use these when reconnaissance reveals opportunities")
            for i, tech in enumerate(targeted_attacks[:5], 1):
                name = tech['technique'][:55]
                rate = tech['success_rate'] * 100
                examples = tech['usage_count']
                report_lines.append(f"   {i}. {name:<55} {rate:>5.0f}% ({examples}x)")
            report_lines.append("")
        
        # Phase 4: Post-Foothold
        if post_foothold:
            report_lines.append("PHASE 4: POST-FOOTHOLD (After initial access)")
            for i, tech in enumerate(post_foothold[:3], 1):
                name = tech['technique'][:55]
                rate = tech['success_rate'] * 100
                examples = tech['usage_count']
                report_lines.append(f"   {i}. {name:<55} {rate:>5.0f}% ({examples}x)")
            report_lines.append("")
        
        # Time estimates by phase
        recon_time = "45-90 minutes" if len(core_recon) > 2 else "30-45 minutes"
        quick_time = f"{len(quick_wins) * 2}-{len(quick_wins) * 5} minutes" if quick_wins else "0 minutes"
        
        report_lines.append("TIME ESTIMATES:")
        report_lines.append(f"   Phase 1 (Recon): ~{recon_time}")
        report_lines.append(f"   Phase 2 (Quick wins): ~{quick_time}")
        report_lines.append(f"   Phase 3 (Targeted): Depends on findings")
        report_lines.append(f"   Phase 4 (Post-foothold): After compromise")
        report_lines.append("")
        
        # Practical guidance
        report_lines.append("STRATEGY:")
        if core_recon:
            best_recon = core_recon[0]['technique']
            report_lines.append(f"   1. Start with '{best_recon}' - reveals attack surface")
        if quick_wins:
            best_quick = quick_wins[0]['technique']
            report_lines.append(f"   2. Quick check: '{best_quick}' - might get lucky")
        if targeted_attacks:
            best_targeted = targeted_attacks[0]['technique']
            report_lines.append(f"   3. If recon reveals opportunity: '{best_targeted}'")
        
        report_lines.append("")
        report_lines.append("Remember: Reconnaissance drives targeting - always start with Phase 1!")
        
        return "\n".join(report_lines)
    
    def generate_technique_priority_list(self, canonical_scenario: str) -> str:
        """Pentesting workflow-based priority list"""
        
        techniques = self.analytics.get_technique_success_rates(canonical_scenario)
        if not techniques:
            return "No technique data available"
        
        # Group by workflow phases
        workflow_phases = {
            'recon': [],
            'quick': [],
            'targeted': [],
            'post': []
        }
        
        for tech in techniques:
            tech_name = tech['technique'].lower()
            
            if any(word in tech_name for word in [
                'directory enumeration', 'web enumeration', 'service enumeration',
                'port scan', 'version detection', 'subdomain', 'dns enumeration'
            ]):
                workflow_phases['recon'].append(tech)
            elif any(word in tech_name for word in [
                'anonymous', 'default credential', 'null session', 'guest access'
            ]):
                workflow_phases['quick'].append(tech)
            elif any(word in tech_name for word in [
                'privilege escalation', 'lateral movement', 'persistence'
            ]):
                workflow_phases['post'].append(tech)
            else:
                workflow_phases['targeted'].append(tech)
        
        # Generate workflow-based priority list
        report_lines = []
        scenario_display = canonical_scenario.replace('_', ' ').title()
        report_lines.append(f"WORKFLOW ORDER - {scenario_display}")
        report_lines.append("=" * 50)
        
        priority = 1
        
        # Phase 1: Reconnaissance
        if workflow_phases['recon']:
            report_lines.append("")
            report_lines.append("RECONNAISSANCE (Do first):")
            for tech in sorted(workflow_phases['recon'], key=lambda x: x['success_rate'], reverse=True)[:4]:
                name = tech['technique'][:35]
                rate = tech['success_rate'] * 100
                examples = tech['usage_count']
                report_lines.append(f"{priority:2d}. {name:<37} {rate:>5.0f}% ({examples}x)")
                priority += 1
        
        # Phase 2: Quick Wins
        if workflow_phases['quick']:
            report_lines.append("")
            report_lines.append("QUICK CHECKS (30 seconds each):")
            for tech in sorted(workflow_phases['quick'], key=lambda x: x['success_rate'], reverse=True)[:3]:
                name = tech['technique'][:35]
                rate = tech['success_rate'] * 100
                examples = tech['usage_count']
                report_lines.append(f"{priority:2d}. {name:<37} {rate:>5.0f}% ({examples}x)")
                priority += 1
        
        # Phase 3: Targeted Attacks
        if workflow_phases['targeted']:
            report_lines.append("")
            report_lines.append("TARGETED (Based on recon):")
            for tech in sorted(workflow_phases['targeted'], key=lambda x: x['success_rate'], reverse=True)[:4]:
                name = tech['technique'][:35]
                rate = tech['success_rate'] * 100
                examples = tech['usage_count']
                report_lines.append(f"{priority:2d}. {name:<37} {rate:>5.0f}% ({examples}x)")
                priority += 1
        
        # Phase 4: Post-Foothold
        if workflow_phases['post']:
            report_lines.append("")
            report_lines.append("POST-FOOTHOLD (After access):")
            for tech in sorted(workflow_phases['post'], key=lambda x: x['success_rate'], reverse=True)[:3]:
                name = tech['technique'][:35]
                rate = tech['success_rate'] * 100
                examples = tech['usage_count']
                report_lines.append(f"{priority:2d}. {name:<37} {rate:>5.0f}% ({examples}x)")
                priority += 1
        
        report_lines.append("")
        report_lines.append("Follow phases in order for best results")
        
        return "\n".join(report_lines)
    
    def generate_technique_recommendation(self, ports: List[int], services: List[str] = None) -> str:
        """Quick technique recommendations based on ports/services"""
        
        recommendations = []
        
        # Port-based recommendations with realistic success estimates
        port_recommendations = {
            21: ("FTP Enumeration", "Check for anonymous access, version info", 75),
            22: ("SSH Enumeration", "Version detection, user enumeration", 85),
            53: ("DNS Enumeration", "Zone transfers, subdomain discovery", 60),
            80: ("Web Directory Enumeration", "Directory/file discovery", 80),
            88: ("Kerberos Attacks", "AS-REP roasting, user enumeration", 70),
            135: ("RPC Enumeration", "Endpoint mapping, user enumeration", 65),
            139: ("NetBIOS Enumeration", "Share discovery, null sessions", 70),
            389: ("LDAP Enumeration", "Anonymous bind, user/group enum", 75),
            443: ("HTTPS Enumeration", "Certificate info, directory enum", 80),
            445: ("SMB Enumeration", "Share access, user enumeration", 85),
            1433: ("MSSQL Enumeration", "Default creds, version detection", 60),
            3306: ("MySQL Enumeration", "Default creds, version detection", 55),
            3389: ("RDP Enumeration", "User enumeration, weak creds", 50),
            5432: ("PostgreSQL Enumeration", "Default creds, version detection", 55)
        }
        
        for port in ports[:10]:  # Limit to top 10 ports
            if port in port_recommendations:
                technique, description, success_rate = port_recommendations[port]
                recommendations.append(f"Port {port:<5} → {technique:<25} ({success_rate}% success)")
                recommendations.append(f"          {description}")
                recommendations.append("")
        
        if not recommendations:
            recommendations.append("No specific port-based recommendations")
            recommendations.append("   Try general enumeration: nmap, web discovery, service detection")
        
        return "\n".join(recommendations)
    
    def _estimate_testing_time(self, technique_count: int) -> str:
        """Estimate time needed for technique testing"""
        
        if technique_count <= 2:
            return "30-45 minutes"
        elif technique_count <= 4:
            return "1-2 hours"
        elif technique_count <= 6:
            return "2-3 hours"
        else:
            return "3+ hours"

def main():
    """Test the actionable intelligence system"""
    
    from intelligence_core import IntelligenceDatabase
    from intelligence_analytics import IntelligenceAnalytics
    
    # Initialize
    db = IntelligenceDatabase("intelligence_db")
    analytics = IntelligenceAnalytics(db)
    actionable = ActionableIntelligence(analytics)
    
    # Test with a scenario
    test_scenario = "miscellaneous_attacks"
    
    print("ACTIONABLE INTELLIGENCE TEST")
    print("=" * 50)
    
    # Generate pentester guidance
    guidance = actionable.generate_pentester_guidance(test_scenario)
    print(guidance)
    
    print("\n" + "=" * 50)
    
    # Generate priority list
    priority_list = actionable.generate_technique_priority_list(test_scenario)
    print(priority_list)
    
    print("\n" + "=" * 50)
    
    # Test port-based recommendations
    test_ports = [22, 80, 443, 445, 3389]
    port_recs = actionable.generate_technique_recommendation(test_ports)
    print("PORT-BASED RECOMMENDATIONS:")
    print(port_recs)

if __name__ == "__main__":
    main()