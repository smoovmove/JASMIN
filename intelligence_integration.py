#!/usr/bin/env python3

"""
Enhanced Intelligence Integration for JARVIS - Database-Driven
Integrates with the enhanced intelligence matcher using 0xdf writeup data
"""

import json
import sqlite3
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import defaultdict

# Import the enhanced statistical engine
try:
    from statistical_confidence_engine import IntegratedStatisticalEngine, ConfidenceResult
    from pattern_discovery_engine import EnhancedPatternDiscoveryEngine
    ENHANCED_ENGINE_AVAILABLE = True
except ImportError:
    print("[!] Enhanced statistical engine not available")
    ENHANCED_ENGINE_AVAILABLE = False

# Import the enhanced intelligence matcher
try:
    from intelligence_matcher import EnhancedIntelligenceMatcher
    ENHANCED_MATCHER_AVAILABLE = True
except ImportError:
    # Fallback to original matcher
    try:
        from intelligence_matcher import IntelligenceMatcher as EnhancedIntelligenceMatcher
        ENHANCED_MATCHER_AVAILABLE = True
        print("[*] Using fallback intelligence matcher")
    except ImportError:
        print("[!] No intelligence matcher available")
        ENHANCED_MATCHER_AVAILABLE = False

class EnhancedIntelligenceIntegration:
    """Main integration class optimized for 0xdf database intelligence"""
    
    def __init__(self, db_path: str = "/home/saint/Documents/Jarvis/intelligence.db"):
        self.db_path = db_path
        self.statistical_engine = None
        self.pattern_engine = None
        self.matcher = None
        self.initialized = False
        self.cache = {}
        
        # Performance tracking
        self.analysis_count = 0
        self.last_analysis_time = None
        
        # Initialize engines with error handling
        self._safe_initialize()
    
    def _safe_initialize(self):
        """Safely initialize engines with comprehensive error handling"""
        try:
            print("[*] Initializing JARVIS Intelligence System...")
            
            # Check database availability
            if not Path(self.db_path).exists():
                print(f"[!] Intelligence database not found: {self.db_path}")
                print("[!] Run database creation script to build the database")
                return
            
            # Initialize enhanced matcher first (most important)
            if ENHANCED_MATCHER_AVAILABLE:
                try:
                    self.matcher = EnhancedIntelligenceMatcher(self.db_path)
                    print("[+] Enhanced intelligence matcher loaded")
                    
                    # Test database connection
                    stats = self.matcher.get_database_stats()
                    if 'scenarios' in stats:
                        print(f"    ✓ Database: {stats['scenarios']} scenarios, {stats['techniques']} techniques")
                    
                except Exception as e:
                    print(f"[!] Enhanced matcher failed to load: {e}")
                    self.matcher = None
            
            # Initialize statistical engine if available
            if ENHANCED_ENGINE_AVAILABLE:
                try:
                    self.statistical_engine = IntegratedStatisticalEngine(self.db_path)
                    print("[+] Statistical confidence engine loaded")
                except Exception as e:
                    print(f"[!] Statistical engine failed to load: {e}")
                    self.statistical_engine = None
                
                # Initialize pattern discovery engine
                try:
                    self.pattern_engine = EnhancedPatternDiscoveryEngine(self.db_path)
                    print("[+] Pattern discovery engine loaded")
                except Exception as e:
                    print(f"[!] Pattern engine failed to load: {e}")
                    self.pattern_engine = None
            
            # System is ready if we have at least the matcher
            if self.matcher:
                self.initialized = True
                print("[+] JARVIS Intelligence System ready")
                print(f"    ✓ Drawing from 0xdf writeup database")
            else:
                print("[!] Intelligence system failed to initialize - no matcher available")
                
        except Exception as e:
            print(f"[!] Intelligence system initialization failed: {e}")
            self.initialized = False
    
    def auto_analyze_scan_results(self, env: Dict) -> None:
        """
        Automatically analyze scan results using enhanced database-driven intelligence
        """
        if not self.initialized or not self.matcher:
            print("[!] Intelligence system not available - run basic analysis")
            self._run_basic_analysis(env)
            return
        
        print("\n" + "="*70)
        print("🧠 JARVIS INTELLIGENCE SYSTEM - ANALYZING TARGET")
        print("="*70)
        
        # Performance tracking
        start_time = datetime.now()
        self.analysis_count += 1
        
        # Extract comprehensive scan data
        print("[1/5] 🔍 Extracting scan data...")
        scan_data = self._extract_comprehensive_scan_data(env)
        if not scan_data:
            print("[!] No scan data found for analysis")
            return
        
        ports = list(scan_data.get('ports', []))
        services = scan_data.get('services', [])
        os_info = scan_data.get('os', None)
        hostnames = list(scan_data.get('hostnames', []))
        
        print(f"    ✓ Found: {len(ports)} ports, {len(services)} services")
        if os_info:
            print(f"    ✓ OS: {os_info}")
        if hostnames:
            print(f"    ✓ Hostnames: {', '.join(hostnames[:3])}")
        
        # Enhanced confidence calculation using statistical engine
        confidence_results = {}
        if self.statistical_engine:
            print("[2/5] 🧮 Running statistical confidence analysis...")
            try:
                confidence_results = self.statistical_engine.calculate_confidence(
                    ports, services, os_info
                )
                print(f"    ✓ Analyzed {len(confidence_results)} environment types")
                
            except Exception as e:
                print(f"[!] Statistical analysis failed: {e}")
                confidence_results = {}
        else:
            print("[2/5] ⚠️  Statistical engine not available - using matcher only")
        
        # Get database-driven attack recommendations
        print("[3/5] 🎯 Getting database-driven attack recommendations...")
        recommendations = {}
        try:
            # Determine environment type from confidence results
            env_type = None
            if confidence_results:
                # Get highest confidence environment
                best_env = max(confidence_results.items(), key=lambda x: x[1].confidence)
                env_type = best_env[0]
                print(f"    ✓ Primary environment: {env_type} ({best_env[1].confidence:.1f}% confidence)")
            
            # Get comprehensive recommendations from database
            recommendations = self.matcher.get_database_optimized_recommendations(
                ports=ports,
                services=services,
                env_type=env_type,
                os_detected=os_info
            )
            
            print(f"    ✓ Generated {recommendations['summary']['total_techniques']} techniques")
            print(f"    ✓ High priority: {len(recommendations['high_priority'])} techniques")
            print(f"    ✓ Medium priority: {len(recommendations['medium_priority'])} techniques")
            print(f"    ✓ Recommended tools: {len(recommendations['summary']['recommended_tools'])}")
            
        except Exception as e:
            print(f"[!] Recommendation generation failed: {e}")
            recommendations = {}
        
        # Display enhanced results
        print("[4/5] 📊 Displaying intelligence results...")
        self._display_enhanced_results(confidence_results, recommendations, scan_data, env)
        
        # Save comprehensive intelligence
        print("[5/5] 💾 Saving intelligence data...")
        intelligence_file = self._save_comprehensive_intelligence(env, confidence_results, recommendations, scan_data)
        
        # Update JARVIS notes
        self._update_jarvis_notes(env, confidence_results, recommendations, scan_data)
        
        # Performance summary
        elapsed = (datetime.now() - start_time).total_seconds()
        self.last_analysis_time = elapsed
        
        print("\n" + "="*70)
        print(f"✅ INTELLIGENCE ANALYSIS COMPLETE ({elapsed:.1f}s)")
        print(f"📁 Results saved to: {intelligence_file.name}")
        print("💡 Use 'intel dashboard' to view summary")
        print("🎯 Use 'intel suggest' for attack recommendations")
        print("="*70)
    
    def _extract_comprehensive_scan_data(self, env: Dict) -> Optional[Dict]:
        """Extract comprehensive data from all available scan files (XML and text)"""
        outdir = Path(env.get('OUTDIR', ''))
        boxname = env.get('BOXNAME', '')
        
        # Initialize comprehensive scan data
        scan_data = {
            'ports': set(),
            'services': [],
            'os': None,
            'hostnames': set(),
            'scan_files_used': [],
            'service_details': {},  # port -> detailed service info
            'os_fingerprints': [],  # multiple OS guesses
            'scan_timestamps': []
        }
        
        # Find XML files first (preferred format)
        xml_patterns = [
            f"{boxname}_tcp*.xml",
            f"{boxname}_script*.xml", 
            f"{boxname}_service*.xml",
            f"{boxname}*.xml"
        ]
        
        xml_files = []
        for pattern in xml_patterns:
            xml_files.extend(outdir.glob(pattern))
        
        # Process XML files
        for xml_file in xml_files:
            try:
                self._parse_xml_file(xml_file, scan_data)
                scan_data['scan_files_used'].append(str(xml_file))
            except Exception as e:
                print(f"    ⚠️  Failed to parse XML file {xml_file}: {e}")
        
        # Find text files as fallback
        text_patterns = [
            f"{boxname}_tcp*.txt",
            f"{boxname}_script*.txt",
            f"{boxname}_service*.txt",
            f"{boxname}*.txt"
        ]
        
        text_files = []
        for pattern in text_patterns:
            text_files.extend(outdir.glob(pattern))
        
        # Process text files
        for text_file in text_files:
            try:
                self._parse_text_file(text_file, scan_data)
                scan_data['scan_files_used'].append(str(text_file))
            except Exception as e:
                print(f"    ⚠️  Failed to parse text file {text_file}: {e}")
        
        # Convert sets to lists for JSON serialization
        scan_data['ports'] = sorted(list(scan_data['ports']))
        scan_data['hostnames'] = sorted(list(scan_data['hostnames']))
        
        return scan_data if scan_data['ports'] else None
    
    def _parse_xml_file(self, xml_file: Path, scan_data: Dict):
        """Parse nmap XML file for comprehensive data"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Extract scan timestamp
            scan_start = root.get('startstr')
            if scan_start:
                scan_data['scan_timestamps'].append(scan_start)
            
            # Process each host
            for host in root.findall('host'):
                # Extract hostnames
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    for hostname in hostnames.findall('hostname'):
                        name = hostname.get('name')
                        if name:
                            scan_data['hostnames'].add(name)
                
                # Extract OS information
                os_elem = host.find('os')
                if os_elem is not None:
                    for osmatch in os_elem.findall('osmatch'):
                        os_name = osmatch.get('name')
                        accuracy = osmatch.get('accuracy', '0')
                        if os_name and int(accuracy) > 80:
                            scan_data['os'] = os_name
                            scan_data['os_fingerprints'].append({
                                'name': os_name,
                                'accuracy': int(accuracy)
                            })
                
                # Extract ports and services
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port in ports_elem.findall('port'):
                        port_id = int(port.get('portid'))
                        protocol = port.get('protocol', 'tcp')
                        
                        # Check if port is open
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            scan_data['ports'].add(port_id)
                            
                            # Extract service information
                            service = port.find('service')
                            if service is not None:
                                service_name = service.get('name', '')
                                service_product = service.get('product', '')
                                service_version = service.get('version', '')
                                
                                if service_name:
                                    scan_data['services'].append(service_name)
                                
                                # Store detailed service info
                                scan_data['service_details'][port_id] = {
                                    'name': service_name,
                                    'product': service_product,
                                    'version': service_version,
                                    'protocol': protocol
                                }
        
        except Exception as e:
            print(f"    ⚠️  XML parsing error: {e}")
    
    def _parse_text_file(self, text_file: Path, scan_data: Dict):
        """Parse nmap text file for basic port information"""
        try:
            with open(text_file, 'r') as f:
                content = f.read()
            
            # Extract ports using regex
            port_pattern = r'(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)'
            matches = re.findall(port_pattern, content)
            
            for match in matches:
                port_num = int(match[0])
                protocol = match[1]
                state = match[2]
                service = match[3]
                
                if state == 'open':
                    scan_data['ports'].add(port_num)
                    scan_data['services'].append(service)
                    
                    # Store basic service info
                    scan_data['service_details'][port_num] = {
                        'name': service,
                        'protocol': protocol,
                        'state': state
                    }
            
            # Extract OS information
            os_pattern = r'OS:\s+(.+)'
            os_matches = re.findall(os_pattern, content)
            if os_matches:
                scan_data['os'] = os_matches[0].strip()
        
        except Exception as e:
            print(f"    ⚠️  Text parsing error: {e}")
    
    def _display_enhanced_results(self, confidence_results: Dict, recommendations: Dict, 
                                 scan_data: Dict, env: Dict):
        """Display enhanced results with database-driven intelligence"""
        
        # Display confidence results if available
        if confidence_results:
            print("\n🎯 ENVIRONMENT CLASSIFICATION RESULTS")
            print("─" * 60)
            
            # Sort by confidence
            sorted_results = sorted(confidence_results.items(), 
                                  key=lambda x: x[1].confidence, 
                                  reverse=True)
            
            for i, (env_type, result) in enumerate(sorted_results[:5], 1):
                confidence = result.confidence
                uncertainty = result.uncertainty
                
                # Create confidence bar
                bar_length = 8
                filled_length = int(bar_length * confidence / 100)
                conf_bar = "█" * filled_length + "░" * (bar_length - filled_length)
                
                # Determine priority level
                if confidence >= 80:
                    priority = "🔴 VERY HIGH"
                elif confidence >= 60:
                    priority = "🟠 HIGH"
                elif confidence >= 40:
                    priority = "🟡 MEDIUM"
                else:
                    priority = "🟢 LOW"
                
                env_display = env_type.replace('_', ' ').upper()
                print(f"{i}. {priority} {env_display}")
                print(f"   Confidence: {confidence:.1f}% (±{uncertainty:.1f}%) [{conf_bar}]")
                print(f"   Evidence: {result.evidence_count} patterns | Method: {result.detection_method}")
                print()
        
        # Display database-driven recommendations
        if recommendations:
            print("🎯 DATABASE-DRIVEN ATTACK RECOMMENDATIONS")
            print("─" * 60)
            
            # Show summary statistics
            summary = recommendations.get('summary', {})
            print(f"📊 Analysis Summary:")
            print(f"   Total Techniques: {summary.get('total_techniques', 0)}")
            print(f"   Source Scenarios: {summary.get('source_scenarios', 0)}")
            print(f"   Data Confidence: {summary.get('data_confidence', 'medium')}")
            print(f"   Technique Diversity: {summary.get('technique_diversity', 0)} categories")
            print()
            
            # Show high priority techniques
            high_priority = recommendations.get('high_priority', [])
            if high_priority:
                print("🔴 HIGH PRIORITY TECHNIQUES:")
                for i, tech in enumerate(high_priority[:5], 1):
                    success_rate = tech.get('success_rate', 0)
                    complexity = tech.get('complexity', 'Unknown')
                    scenario_count = tech.get('scenario_count', 0)
                    
                    print(f"   {i}. {tech['technique_name']}")
                    print(f"      Success: {success_rate:.1%} | Complexity: {complexity}")
                    print(f"      Used in: {scenario_count} scenarios")
                    print(f"      Tools: {', '.join(tech.get('primary_tools', [])[:3])}")
                    print()
            
            # Show medium priority techniques
            medium_priority = recommendations.get('medium_priority', [])
            if medium_priority:
                print("🟠 MEDIUM PRIORITY TECHNIQUES:")
                for i, tech in enumerate(medium_priority[:3], 1):
                    success_rate = tech.get('success_rate', 0)
                    complexity = tech.get('complexity', 'Unknown')
                    
                    print(f"   {i}. {tech['technique_name']}")
                    print(f"      Success: {success_rate:.1%} | Complexity: {complexity}")
                    print(f"      Tools: {', '.join(tech.get('primary_tools', [])[:2])}")
                    print()
            
            # Show attack timeline
            timeline = summary.get('attack_timeline', [])
            if timeline:
                print("⏱️ SUGGESTED ATTACK TIMELINE:")
                for phase in timeline:
                    phase_name = phase.get('phase_name', 'Unknown Phase')
                    estimated_time = phase.get('estimated_time', 'Unknown')
                    priority = phase.get('priority', 'medium')
                    
                    priority_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(priority, "🟡")
                    
                    print(f"   Phase {phase.get('phase', 0)}: {phase_name} ({estimated_time}) {priority_icon}")
                    for technique in phase.get('techniques', []):
                        print(f"     → {technique}")
                    print()
    
    def _save_comprehensive_intelligence(self, env: Dict, confidence_results: Dict, 
                                       recommendations: Dict, scan_data: Dict) -> Path:
        """Save comprehensive intelligence data to file"""
        
        outdir = Path(env.get('OUTDIR', ''))
        boxname = env.get('BOXNAME', '')
        ip = env.get('IP', '')
        
        # Create intelligence directory
        intel_dir = outdir / "intelligence"
        intel_dir.mkdir(exist_ok=True)
        
        # Prepare comprehensive intelligence report
        intel_report = {
            'metadata': {
                'version': '3.0',
                'timestamp': datetime.now().isoformat(),
                'analysis_engine': 'JARVIS Enhanced Database-Driven Intelligence',
                'analysis_count': self.analysis_count,
                'analysis_duration': self.last_analysis_time,
                'database_path': str(self.db_path)
            },
            'target': {
                'name': boxname,
                'ip': ip,
                'ports': scan_data.get('ports', []),
                'services': scan_data.get('services', []),
                'os': scan_data.get('os'),
                'hostnames': scan_data.get('hostnames', []),
                'service_details': scan_data.get('service_details', {}),
                'scan_files_analyzed': scan_data.get('scan_files_used', [])
            },
            'confidence_analysis': {},
            'recommendations': recommendations,
            'database_stats': {}
        }
        
        # Add confidence results
        if confidence_results:
            for env_type, result in confidence_results.items():
                intel_report['confidence_analysis'][env_type] = {
                    'confidence': result.confidence,
                    'uncertainty': result.uncertainty,
                    'evidence_count': result.evidence_count,
                    'success_probability': result.success_probability,
                    'detection_method': result.detection_method,
                    'statistical_significance': result.statistical_significance
                }
        
        # Add database statistics
        if self.matcher:
            try:
                intel_report['database_stats'] = self.matcher.get_database_stats()
            except Exception as e:
                print(f"    ⚠️  Could not get database stats: {e}")
        
        # Save intelligence file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        intel_file = intel_dir / f"{boxname}_intelligence_{timestamp}.json"
        
        with open(intel_file, 'w') as f:
            json.dump(intel_report, f, indent=2, default=str)
        
        # Also save as latest
        latest_file = intel_dir / f"{boxname}_intelligence_latest.json"
        with open(latest_file, 'w') as f:
            json.dump(intel_report, f, indent=2, default=str)
        
        return intel_file
    
    def _update_jarvis_notes(self, env: Dict, confidence_results: Dict, 
                           recommendations: Dict, scan_data: Dict):
        """Update JARVIS notes with intelligence findings"""
        
        outdir = Path(env.get('OUTDIR', ''))
        boxname = env.get('BOXNAME', '')
        
        # Prepare notes content
        notes_content = [
            f"\n=== INTELLIGENCE ANALYSIS - {datetime.now().strftime('%Y-%m-%d %H:%M')} ===\n"
        ]
        
        # Add scan summary
        ports = scan_data.get('ports', [])
        services = scan_data.get('services', [])
        notes_content.append(f"📊 Scan Summary: {len(ports)} ports, {len(services)} services")
        
        # Add confidence results
        if confidence_results:
            notes_content.append("\n🎯 Environment Classification:")
            sorted_results = sorted(confidence_results.items(), 
                                  key=lambda x: x[1].confidence, 
                                  reverse=True)
            
            for env_type, result in sorted_results[:3]:
                env_display = env_type.replace('_', ' ').title()
                notes_content.append(f"   • {env_display}: {result.confidence:.1f}% confidence")
        
        # Add top recommendations
        if recommendations:
            high_priority = recommendations.get('high_priority', [])
            if high_priority:
                notes_content.append("\n🔴 High Priority Techniques:")
                for tech in high_priority[:5]:
                    success_rate = tech.get('success_rate', 0)
                    notes_content.append(f"   • {tech['technique_name']} ({success_rate:.1%})")
        
        # Add database statistics
        if self.matcher:
            try:
                stats = self.matcher.get_database_stats()
                notes_content.append(f"\n📚 Database: {stats.get('scenarios', 0)} scenarios analyzed")
            except:
                pass
        
        # Write to notes file
        notes_file = outdir / f"{boxname}_notes.txt"
        with open(notes_file, 'a') as f:
            f.write('\n'.join(notes_content) + '\n')
    
    def _run_basic_analysis(self, env: Dict):
        """Run basic analysis when advanced engines are not available"""
        
        print("\n🔧 BASIC INTELLIGENCE ANALYSIS")
        print("─" * 50)
        
        # Extract basic scan data
        scan_data = self._extract_comprehensive_scan_data(env)
        if not scan_data:
            print("No scan data available for analysis")
            return
        
        ports = scan_data.get('ports', [])
        services = scan_data.get('services', [])
        
        print(f"📊 Found: {len(ports)} ports, {len(services)} services")
        
        # Basic port analysis
        if ports:
            print("\n🔍 Port Analysis:")
            interesting_ports = {
                22: "SSH",
                80: "HTTP",
                443: "HTTPS", 
                445: "SMB",
                3389: "RDP",
                1433: "MSSQL",
                3306: "MySQL"
            }
            
            for port in sorted(ports):
                service_name = interesting_ports.get(port, "Unknown")
                if port in interesting_ports:
                    print(f"   • Port {port}: {service_name} - High value target")
        
        # Basic service analysis
        if services:
            print("\n🔧 Service Analysis:")
            for service in set(services):
                print(f"   • {service}")
        
        print("\n💡 For advanced analysis, ensure intelligence database is available")
    
    def get_intelligence_summary(self, env: Dict) -> Optional[Dict]:
        """Get intelligence summary for current target"""
        
        outdir = Path(env.get('OUTDIR', ''))
        boxname = env.get('BOXNAME', '')
        
        # Try to load latest intelligence file
        intel_file = outdir / "intelligence" / f"{boxname}_intelligence_latest.json"
        if intel_file.exists():
            try:
                with open(intel_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[!] Failed to load intelligence file: {e}")
        
        # Fallback to most recent timestamped file
        intel_dir = outdir / "intelligence"
        if intel_dir.exists():
            intel_files = list(intel_dir.glob(f"{boxname}_intelligence_*.json"))
            if intel_files:
                # Get most recent file
                latest = max(intel_files, key=lambda f: f.stat().st_mtime)
                try:
                    with open(latest, 'r') as f:
                        return json.load(f)
                except Exception as e:
                    print(f"[!] Failed to load intelligence file: {e}")
        
        return None
    
    def get_performance_stats(self) -> Dict:
        """Get performance statistics for the intelligence system"""
        return {
            'analysis_count': self.analysis_count,
            'last_analysis_time': self.last_analysis_time,
            'initialized': self.initialized,
            'engines_available': {
                'statistical': self.statistical_engine is not None,
                'pattern': self.pattern_engine is not None,
                'enhanced_matcher': self.matcher is not None
            }
        }


# Global instance for integration
_intelligence_integration = None

def init_intelligence_system():
    """Initialize the global intelligence system"""
    global _intelligence_integration
    if _intelligence_integration is None:
        _intelligence_integration = EnhancedIntelligenceIntegration()
    return _intelligence_integration

def auto_analyze_scan_results(env: Dict):
    """Auto-analyze scan results - called by scans.py"""
    global _intelligence_integration
    if _intelligence_integration is None:
        _intelligence_integration = init_intelligence_system()
    
    _intelligence_integration.auto_analyze_scan_results(env)

def handle_intel_command(env: Dict, tokens: List[str]):
    """Enhanced intel command handler with comprehensive subcommands"""
    global _intelligence_integration
    if _intelligence_integration is None:
        _intelligence_integration = init_intelligence_system()
    
    if not env:
        print("[!] No active session for intelligence analysis")
        return env
    
    if len(tokens) < 2:
        _show_intel_help()
        return env
    
    subcommand = tokens[1].lower()
    
    try:
        if subcommand == "dashboard":
            _show_intelligence_dashboard(env)
        elif subcommand == "suggest":
            _show_attack_suggestions(env)
        elif subcommand == "analyze":
            _intelligence_integration.auto_analyze_scan_results(env)
        elif subcommand == "show" and len(tokens) >= 3:
            _show_detailed_analysis(env, tokens[2:])
        elif subcommand == "stats":
            _show_performance_stats()
        elif subcommand == "help":
            _show_intel_help()
        else:
            print("[!] Unknown intel command. Use 'intel help' for available commands")
    
    except Exception as e:
        print(f"[!] Intelligence command failed: {e}")
    
    return env

def _show_intel_help():
    """Show comprehensive intel command help"""
    print("""
🧠 JARVIS Intelligence Commands:

  intel dashboard          Show intelligence overview for current target
  intel suggest           Get database-driven attack recommendations  
  intel analyze           Re-run intelligence analysis on scan results
  intel show port <n>     Deep analysis of specific port
  intel show service smb   # Analyze SMB attack techniques
  intel stats             # Show system performance & database stats
""")

def _show_intelligence_dashboard(env: Dict):
    """Enhanced intelligence dashboard with database-driven insights"""
    global _intelligence_integration
    
    summary = _intelligence_integration.get_intelligence_summary(env)
    if not summary:
        print("\n🎯 NO INTELLIGENCE DATA AVAILABLE")
        print("─" * 50)
        print("💡 Run a scan with '--intel' flag to generate intelligence")
        print("📊 Example: fs --intel")
        return
    
    print("\n🧠 INTELLIGENCE DASHBOARD")
    print("=" * 60)
    
    # Target summary
    target = summary.get('target', {})
    print(f"🎯 Target: {target.get('name', 'Unknown')} ({target.get('ip', 'Unknown')})")
    print(f"📊 Ports: {len(target.get('ports', []))} | Services: {len(target.get('services', []))}")
    if target.get('os'):
        print(f"💻 OS: {target.get('os')}")
    
    # Database statistics
    db_stats = summary.get('database_stats', {})
    if db_stats:
        print(f"\n📚 Database Intelligence:")
        print(f"   • Scenarios: {db_stats.get('scenarios', 0):,}")
        print(f"   • Techniques: {db_stats.get('techniques', 0):,}")
        print(f"   • Port Mappings: {db_stats.get('port_mappings', 0):,}")
        print(f"   • Service Mappings: {db_stats.get('service_mappings', 0):,}")
    
    # Environment classification
    confidence = summary.get('confidence_analysis', {})
    if confidence:
        print(f"\n🎯 ENVIRONMENT CLASSIFICATION:")
        
        # Sort by confidence
        sorted_confidence = sorted(confidence.items(), 
                                 key=lambda x: x[1]['confidence'], 
                                 reverse=True)
        
        for env_type, result in sorted_confidence[:3]:
            conf = result['confidence']
            uncertainty = result.get('uncertainty', 0)
            
            # Create confidence bar
            bar_length = 8
            filled_length = int(bar_length * conf / 100)
            conf_bar = "█" * filled_length + "░" * (bar_length - filled_length)
            
            env_display = env_type.replace('_', ' ').title()
            print(f"   {conf:.1f}% (±{uncertainty:.1f}%) [{conf_bar}] {env_display}")
    
    # Attack recommendations summary
    recommendations = summary.get('recommendations', {})
    if recommendations:
        rec_summary = recommendations.get('summary', {})
        print(f"\n🎯 ATTACK RECOMMENDATIONS:")
        print(f"   • Total Techniques: {rec_summary.get('total_techniques', 0)}")
        print(f"   • Source Scenarios: {rec_summary.get('source_scenarios', 0)}")
        print(f"   • High Priority: {len(recommendations.get('high_priority', []))}")
        print(f"   • Medium Priority: {len(recommendations.get('medium_priority', []))}")
        print(f"   • Recommended Tools: {len(rec_summary.get('recommended_tools', []))}")
    
    # Analysis metadata
    metadata = summary.get('metadata', {})
    if metadata:
        print(f"\n📊 Analysis Metadata:")
        print(f"   • Version: {metadata.get('version', 'Unknown')}")
        print(f"   • Duration: {metadata.get('analysis_duration', 0):.1f}s")
        print(f"   • Timestamp: {metadata.get('timestamp', 'Unknown')}")
    
    print(f"\n💡 Commands:")
    print(f"   intel suggest    - Get detailed attack recommendations")
    print(f"   intel show port  - Analyze specific ports")
    print(f"   intel stats      - Show system performance")

def _show_attack_suggestions(env: Dict):
    """Enhanced attack suggestions with database-driven recommendations"""
    global _intelligence_integration
    
    summary = _intelligence_integration.get_intelligence_summary(env)
    if not summary:
        print("\n🎯 NO INTELLIGENCE DATA FOR RECOMMENDATIONS")
        print("─" * 50)
        print("💡 Run 'intel analyze' to generate attack suggestions")
        return
    
    print("\n🎯 DATABASE-DRIVEN ATTACK RECOMMENDATIONS")
    print("=" * 70)
    
    # Get target data
    target = summary.get('target', {})
    recommendations = summary.get('recommendations', {})
    
    if not recommendations:
        print("⚠️  No recommendations available")
        return
    
    print(f"📋 Target: {target.get('name')} ({target.get('ip')})")
    
    # Show database statistics
    db_stats = summary.get('database_stats', {})
    if db_stats:
        print(f"📚 Intelligence Source: {db_stats.get('scenarios', 0)} scenarios, {db_stats.get('techniques', 0)} techniques")
    
    # High priority recommendations
    high_priority = recommendations.get('high_priority', [])
    if high_priority:
        print(f"\n🔴 HIGH PRIORITY TECHNIQUES:")
        print("─" * 45)
        
        for i, tech in enumerate(high_priority[:5], 1):
            success_rate = tech.get('success_rate', 0)
            complexity = tech.get('complexity', 'Unknown')
            scenario_count = tech.get('scenario_count', 0)
            tools = tech.get('primary_tools', [])
            
            print(f"{i}. {tech['technique_name']}")
            print(f"   Success: {success_rate:.1%} | Complexity: {complexity}")
            print(f"   Used in: {scenario_count} scenarios")
            print(f"   Tools: {', '.join(tools[:3])}")
            
            # Show example commands if available
            commands = tech.get('example_commands', [])
            if commands:
                print(f"   Example: {commands[0]}")
            print()
    
    # Medium priority recommendations
    medium_priority = recommendations.get('medium_priority', [])
    if medium_priority:
        print(f"🟠 MEDIUM PRIORITY TECHNIQUES:")
        print("─" * 45)
        
        for i, tech in enumerate(medium_priority[:3], 1):
            success_rate = tech.get('success_rate', 0)
            complexity = tech.get('complexity', 'Unknown')
            tools = tech.get('primary_tools', [])
            
            print(f"{i}. {tech['technique_name']}")
            print(f"   Success: {success_rate:.1%} | Complexity: {complexity}")
            print(f"   Tools: {', '.join(tools[:2])}")
            print()
    
    # Attack timeline
    rec_summary = recommendations.get('summary', {})
    timeline = rec_summary.get('attack_timeline', [])
    if timeline:
        print(f"⏱️ SUGGESTED ATTACK TIMELINE:")
        print("─" * 45)
        
        for phase in timeline:
            phase_num = phase.get('phase', 0)
            phase_name = phase.get('phase_name', 'Unknown Phase')
            estimated_time = phase.get('estimated_time', 'Unknown')
            priority = phase.get('priority', 'medium')
            
            # Priority icon
            priority_icons = {
                'critical': '🔴',
                'high': '🟠', 
                'medium': '🟡',
                'low': '🟢'
            }
            priority_icon = priority_icons.get(priority, '🟡')
            
            print(f"Phase {phase_num}: {phase_name} ({estimated_time}) {priority_icon}")
            
            for technique in phase.get('techniques', []):
                print(f"   → {technique}")
            print()
    
    # Recommended tools summary
    tools = rec_summary.get('recommended_tools', [])
    if tools:
        print(f"🔧 RECOMMENDED TOOLS:")
        print("─" * 45)
        
        # Group tools by category (basic categorization)
        web_tools = [t for t in tools if any(keyword in t.lower() for keyword in ['web', 'http', 'url', 'dir', 'gobuster', 'nikto'])]
        enum_tools = [t for t in tools if any(keyword in t.lower() for keyword in ['enum', 'scan', 'nmap', 'masscan'])]
        exploit_tools = [t for t in tools if any(keyword in t.lower() for keyword in ['exploit', 'shell', 'payload'])]
        other_tools = [t for t in tools if t not in web_tools and t not in enum_tools and t not in exploit_tools]
        
        if enum_tools:
            print(f"   Enumeration: {', '.join(enum_tools[:5])}")
        if web_tools:
            print(f"   Web Testing: {', '.join(web_tools[:5])}")
        if exploit_tools:
            print(f"   Exploitation: {', '.join(exploit_tools[:5])}")
        if other_tools:
            print(f"   Other: {', '.join(other_tools[:5])}")

def _show_detailed_analysis(env: Dict, args: List[str]):
    """Show detailed analysis for specific ports or services"""
    global _intelligence_integration
    
    if not args:
        print("Usage: intel show <port|service> <value>")
        return
    
    analysis_type = args[0].lower()
    
    if analysis_type == "port" and len(args) >= 2:
        try:
            port = int(args[1])
            _show_port_analysis(env, port)
        except ValueError:
            print(f"Invalid port number: {args[1]}")
    
    elif analysis_type == "service" and len(args) >= 2:
        service = args[1].lower()
        _show_service_analysis(env, service)
    
    else:
        print("Usage: intel show <port|service> <value>")

def _show_port_analysis(env: Dict, port: int):
    """Show detailed port analysis using database intelligence"""
    global _intelligence_integration
    
    if not _intelligence_integration.matcher:
        print(f"⚠️  Enhanced analysis not available for port {port}")
        return
    
    print(f"\n🔍 DETAILED PORT ANALYSIS - Port {port}")
    print("=" * 50)
    
    # Get port-specific techniques from database
    try:
        techniques = _intelligence_integration.matcher.get_port_specific_techniques([port], limit=10)
        
        if techniques:
            print(f"📊 Found {len(techniques)} techniques for port {port}")
            
            # Get database stats for this port
            db_stats = _intelligence_integration.matcher.get_database_stats()
            port_mappings = db_stats.get('port_mappings', 0)
            print(f"📚 Database coverage: {port_mappings:,} port mappings available")
            
            print(f"\n🎯 TECHNIQUES FOR PORT {port}:")
            print("─" * 40)
            
            for i, tech in enumerate(techniques, 1):
                success_rate = tech.get('success_rate', 0)
                complexity = tech.get('complexity', 'Unknown')
                scenario_count = tech.get('scenario_count', 0)
                tools = tech.get('primary_tools', [])
                
                print(f"{i}. {tech['technique_name']}")
                print(f"   Success Rate: {success_rate:.1%}")
                print(f"   Complexity: {complexity}")
                print(f"   Used in: {scenario_count} scenarios")
                
                # Handle tools safely - they might be strings or dicts
                try:
                    if tools:
                        # Extract tool names if they're dicts, otherwise use as strings
                        tool_names = []
                        for tool in tools[:3]:
                            if isinstance(tool, dict):
                                tool_name = tool.get('name', str(tool))
                            else:
                                tool_name = str(tool)
                            tool_names.append(tool_name)
                        print(f"   Tools: {', '.join(tool_names)}")
                    else:
                        print(f"   Tools: None specified")
                except Exception as e:
                    print(f"   Tools: [Error displaying tools: {e}]")
                
                # Show description if available
                description = tech.get('description', '')
                if description:
                    print(f"   Description: {description}")
                
                # Show example commands safely
                try:
                    commands = tech.get('example_commands', [])
                    if commands:
                        if isinstance(commands[0], dict):
                            cmd = commands[0].get('command', str(commands[0]))
                        else:
                            cmd = str(commands[0])
                        print(f"   Example: {cmd}")
                except Exception as e:
                    print(f"   Example: [Error displaying command: {e}]")
                
                print()
        
        else:
            print(f"⚠️  No specific techniques found for port {port}")
            print(f"💡 Port {port} may not be well-covered in the database")
    
    except Exception as e:
        print(f"❌ Error analyzing port {port}: {e}")

def _show_service_analysis(env: Dict, service: str):
    """Show detailed service analysis using database intelligence"""
    global _intelligence_integration
    
    if not _intelligence_integration.matcher:
        print(f"⚠️  Enhanced analysis not available for service {service}")
        return
    
    print(f"\n🔧 DETAILED SERVICE ANALYSIS - {service.upper()}")
    print("=" * 50)
    
    # Get service-specific techniques from database
    try:
        techniques = _intelligence_integration.matcher.get_service_specific_techniques([service], limit=10)
        
        if techniques:
            print(f"📊 Found {len(techniques)} techniques for {service}")
            
            # Get database stats for this service
            db_stats = _intelligence_integration.matcher.get_database_stats()
            service_mappings = db_stats.get('service_mappings', 0)
            print(f"📚 Database coverage: {service_mappings:,} service mappings available")
            
            print(f"\n🎯 TECHNIQUES FOR {service.upper()}:")
            print("─" * 40)
            
            for i, tech in enumerate(techniques, 1):
                success_rate = tech.get('success_rate', 0)
                complexity = tech.get('complexity', 'Unknown')
                scenario_count = tech.get('scenario_count', 0)
                tools = tech.get('primary_tools', [])
                
                print(f"{i}. {tech['technique_name']}")
                print(f"   Success Rate: {success_rate:.1%}")
                print(f"   Complexity: {complexity}")
                print(f"   Used in: {scenario_count} scenarios")
                
                # Handle tools safely - they might be strings or dicts
                try:
                    if tools:
                        # Extract tool names if they're dicts, otherwise use as strings
                        tool_names = []
                        for tool in tools[:3]:
                            if isinstance(tool, dict):
                                tool_name = tool.get('name', str(tool))
                            else:
                                tool_name = str(tool)
                            tool_names.append(tool_name)
                        print(f"   Tools: {', '.join(tool_names)}")
                    else:
                        print(f"   Tools: None specified")
                except Exception as e:
                    print(f"   Tools: [Error displaying tools: {e}]")
                
                # Show matching sources
                try:
                    sources = tech.get('matching_sources', [])
                    if sources:
                        source_names = []
                        for source in sources[:3]:
                            if isinstance(source, dict):
                                source_name = source.get('name', str(source))
                            else:
                                source_name = str(source)
                            source_names.append(source_name)
                        print(f"   Sources: {', '.join(source_names)}")
                except Exception as e:
                    print(f"   Sources: [Error displaying sources: {e}]")
                
                print()
        
        else:
            print(f"⚠️  No specific techniques found for service {service}")
            print(f"💡 Service {service} may not be well-covered in the database")
    
    except Exception as e:
        print(f"❌ Error analyzing service {service}: {e}")

def _show_performance_stats():
    """Show enhanced intelligence system performance statistics"""
    global _intelligence_integration
    
    stats = _intelligence_integration.get_performance_stats()
    
    print("\n📊 INTELLIGENCE SYSTEM STATISTICS")
    print("=" * 50)
    
    print(f"System Status: {'✅ ONLINE' if stats['initialized'] else '❌ OFFLINE'}")
    print(f"Analyses Performed: {stats['analysis_count']}")
    
    if stats['last_analysis_time']:
        print(f"Last Analysis Duration: {stats['last_analysis_time']:.1f}s")
    
    print(f"\n🔧 Engine Status:")
    engines = stats['engines_available']
    print(f"  Enhanced Matcher: {'✅' if engines['enhanced_matcher'] else '❌'}")
    print(f"  Statistical Engine: {'✅' if engines['statistical'] else '❌'}")
    print(f"  Pattern Engine: {'✅' if engines['pattern'] else '❌'}")
    
    # Show database statistics if available
    if _intelligence_integration.matcher:
        try:
            db_stats = _intelligence_integration.matcher.get_database_stats()
            print(f"\n📚 Database Statistics:")
            print(f"  Scenarios: {db_stats.get('scenarios', 0):,}")
            print(f"  Techniques: {db_stats.get('techniques', 0):,}")
            print(f"  Port Mappings: {db_stats.get('port_mappings', 0):,}")
            print(f"  Service Mappings: {db_stats.get('service_mappings', 0):,}")
            print(f"  Cached Techniques: {db_stats.get('cached_techniques', 0):,}")
            print(f"  Cached Ports: {db_stats.get('cached_ports', 0):,}")
            print(f"  Cached Services: {db_stats.get('cached_services', 0):,}")
            
            # Show top environments
            top_envs = db_stats.get('top_environments', {})
            if top_envs:
                print(f"\n🌍 Top Environments:")
                for env, count in list(top_envs.items())[:5]:
                    print(f"  {env}: {count} scenarios")
            
            # Show top techniques
            top_techs = db_stats.get('top_techniques', {})
            if top_techs:
                print(f"\n🔧 Top Techniques:")
                for tech, count in list(top_techs.items())[:5]:
                    print(f"  {tech}: {count} uses")
                    
        except Exception as e:
            print(f"⚠️  Could not retrieve database statistics: {e}")


# Integration test function
def test_enhanced_integration():
    """Test the enhanced intelligence integration"""
    
    print("🧪 Testing Enhanced Intelligence Integration")
    print("=" * 50)
    
    # Test initialization
    integration = EnhancedIntelligenceIntegration()
    print(f"Initialization: {'✅ SUCCESS' if integration.initialized else '❌ FAILED'}")
    
    # Test matcher availability
    if integration.matcher:
        print("✅ Enhanced matcher available")
        stats = integration.matcher.get_database_stats()
        print(f"   Database: {stats.get('scenarios', 0)} scenarios")
    else:
        print("❌ Enhanced matcher not available")
    
    # Test performance stats
    perf_stats = integration.get_performance_stats()
    print(f"Performance tracking: {'✅ WORKING' if perf_stats['analysis_count'] >= 0 else '❌ FAILED'}")
    
    print("\n🎯 Integration ready for JARVIS!")


if __name__ == "__main__":
    test_enhanced_integration()