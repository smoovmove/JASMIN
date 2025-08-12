#!/usr/bin/env python3

"""
Enhanced Intelligence Integration for JASMIN - Database-Driven
Uses old version's display formatting with current variable structure
Maintains compatibility with jasmin.py and cli.py
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

# Import the enhanced statistical engine - keeping current imports
try:
    from statistical_confidence_engine import IntegratedStatisticalEngine, ConfidenceResult
    from pattern_discovery_engine import EnhancedPatternDiscoveryEngine
    ENHANCED_ENGINE_AVAILABLE = True
except ImportError:
    ENHANCED_ENGINE_AVAILABLE = False

# Import the enhanced intelligence matcher - keeping current structure
try:
    from intelligence_matcher import EnhancedIntelligenceMatcher
    ENHANCED_MATCHER_AVAILABLE = True
except ImportError:
    ENHANCED_MATCHER_AVAILABLE = False

class EnhancedIntelligenceIntegration:
    """Main integration class - old version's robustness with current variables"""
    
    def __init__(self, db_path: str = "/home/saint/Documents/Jasmin/intelligence.db", debug=False):
        self.db_path = db_path
        self.statistical_engine = None
        self.pattern_engine = None
        self.matcher = None
        self.initialized = False
        self.cache = {}
        self.debug = debug
        
        # Performance tracking - keeping current variables
        self.analysis_count = 0
        self.last_analysis_time = None
        
        # Initialize engines with old version's robust error handling
        self._safe_initialize()
    
    def _safe_initialize(self):
        """Safely initialize engines - old version's robust approach"""
        try:
            if self.debug:
                print("[*] Initializing JASMIN Intelligence System...")
            
            # Check database availability
            if not Path(self.db_path).exists():
                if self.debug:
                    print(f"[!] Intelligence database not found: {self.db_path}")
                    print("[!] Run 'python intelligence_main.py' to build the database")
                return
            
            # Initialize enhanced matcher first - most important
            if ENHANCED_MATCHER_AVAILABLE:
                try:
                    self.matcher = EnhancedIntelligenceMatcher(self.db_path, debug=self.debug)
                    if self.debug:
                        print("[+] Enhanced intelligence matcher loaded")
                        
                        # Test database connection with old version's approach
                        stats = self.matcher.get_database_stats()
                        if 'scenarios' in stats:
                            print(f"    ✓ Database: {stats['scenarios']} scenarios, {stats['techniques']} techniques")
                    
                except Exception as e:
                    if self.debug:
                        print(f"[!] Enhanced matcher failed to load: {e}")
                    self.matcher = None
            
            # Initialize statistical engine if available
            if ENHANCED_ENGINE_AVAILABLE:
                try:
                    self.statistical_engine = IntegratedStatisticalEngine(
                        confidence_threshold=0.7,
                        debug=self.debug
                    )
                    if self.debug:
                        print("[+] Statistical confidence engine loaded")
                except Exception as e:
                    if self.debug:
                        print(f"[!] Statistical engine failed to load: {e}")
                    self.statistical_engine = None
                
                # Initialize pattern discovery engine
                try:
                    self.pattern_engine = EnhancedPatternDiscoveryEngine(
                        confidence_threshold=0.75,
                        debug=self.debug
                    )
                    if self.debug:
                        print("[+] Pattern discovery engine loaded")
                except Exception as e:
                    if self.debug:
                        print(f"[!] Pattern engine failed to load: {e}")
                    self.pattern_engine = None
            
            # System is ready if we have at least the matcher
            if self.matcher:
                self.initialized = True
                if self.debug:
                    print("[+] JASMIN Intelligence System ready")
                    print(f"    ✓ Drawing from 0xdf writeup database")
            else:
                if self.debug:
                    print("[!] Intelligence system failed to initialize - no matcher available")
                
        except Exception as e:
            if self.debug:
                print(f"[!] Intelligence system initialization failed: {e}")
            self.initialized = False
    
    def auto_analyze_scan_results(self, env: Dict) -> None:
        """
        Automatically analyze scan results - keeping current method signature
        Uses old version's robust analysis flow
        """
        if not self.initialized or not self.matcher:
            print("[!] Intelligence system not available")
            return
        
        start_time = datetime.now()
        self.analysis_count += 1
        
        print("\n🧠 ENHANCED INTELLIGENCE ANALYSIS")
        print("=" * 70)
        
        # Extract scan data with old version's robust approach
        print("[1/5] 📊 Extracting scan data...")
        scan_data = self._extract_comprehensive_scan_data(env)
        if not scan_data:
            print("⚠️  No scan data available for analysis")
            return
        
        ports = list(scan_data.get('ports', []))
        services = scan_data.get('services', [])
        os_info = scan_data.get('os')
        
        print(f"    ✓ Found {len(ports)} ports, {len(services)} services")
        if os_info:
            print(f"    ✓ OS detected: {os_info}")
        
        # Statistical confidence analysis - old version's error handling
        print("[2/5] 📈 Running statistical confidence analysis...")
        confidence_results = {}
        if self.statistical_engine:
            try:
                confidence_results = self.statistical_engine.analyze_scan_results(scan_data)
                print(f"    ✓ Analyzed {len(confidence_results)} environments")
            except Exception as e:
                print(f"    ⚠️  Statistical analysis failed: {e}")
                confidence_results = {}
        else:
            print("    ⚠️  Statistical engine not available - using matcher only")
        
        # Get database-driven attack recommendations
        print("[3/5] 🎯 Getting database-driven attack recommendations...")
        recommendations = {}
        try:
            # Determine environment type from confidence results
            env_type = None
            if confidence_results:
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
            print(f"    ⚠️  Recommendation generation failed: {e}")
            recommendations = {}
        
        # Display enhanced results - old version's clean formatting
        print("[4/5] 📊 Displaying intelligence results...")
        self._display_enhanced_results(confidence_results, recommendations, scan_data, env)
        
        # Save comprehensive intelligence
        print("[5/5] 💾 Saving intelligence data...")
        intelligence_file = self._save_comprehensive_intelligence(env, confidence_results, recommendations, scan_data)
        
        # Update JASMIN notes - old version's approach
        self._update_jasmin_notes(env, confidence_results, recommendations, scan_data)
        
        # Performance summary
        elapsed = (datetime.now() - start_time).total_seconds()
        self.last_analysis_time = elapsed
        
        print("\n" + "="*70)
        print(f"✅ INTELLIGENCE ANALYSIS COMPLETE ({elapsed:.1f}s)")
        if intelligence_file:
            print(f"📁 Results saved to: {intelligence_file.name}")
        print("💡 Use 'intel dashboard' to view summary")
        print("🎯 Use 'intel suggest' for attack recommendations")
        print("="*70)
    
    def _extract_comprehensive_scan_data(self, env: Dict) -> Optional[Dict]:
        """Extract comprehensive data from scan files - old version's robust approach"""
        outdir = Path(env.get('OUTDIR', ''))
        boxname = env.get('BOXNAME', '')
        
        # Initialize comprehensive scan data
        scan_data = {
            'ports': set(),
            'services': [],
            'os': None,
            'hostnames': set(),
            'scan_files_used': [],
            'service_details': {},
            'os_fingerprints': [],
            'scan_timestamps': []
        }
        
        # Find XML files first (preferred format)
        xml_patterns = [
            f"{boxname}_tcp*.xml",
            f"{boxname}_script*.xml", 
            f"{boxname}*.xml",
            "nmap*.xml"
        ]
        
        for pattern in xml_patterns:
            xml_files = list(outdir.glob(pattern))
            for xml_file in xml_files:
                try:
                    # Parse XML with old version's robust error handling
                    data = self._parse_nmap_xml(xml_file)
                    if data:
                        scan_data['ports'].update(data.get('ports', []))
                        scan_data['services'].extend(data.get('services', []))
                        if data.get('os') and not scan_data['os']:
                            scan_data['os'] = data['os']
                        scan_data['hostnames'].update(data.get('hostnames', []))
                        scan_data['scan_files_used'].append(str(xml_file))
                        
                except Exception as e:
                    if self.debug:
                        print(f"    ⚠️  Error parsing {xml_file}: {e}")
                    continue
        
        # Also check text files as fallback
        txt_patterns = [
            f"{boxname}_tcp*.txt",
            f"{boxname}_service*.txt",
            f"{boxname}*.txt"
        ]
        
        for pattern in txt_patterns:
            txt_files = list(outdir.glob(pattern))
            for txt_file in txt_files:
                try:
                    data = self._parse_nmap_text(txt_file)
                    if data:
                        scan_data['ports'].update(data.get('ports', []))
                        scan_data['services'].extend(data.get('services', []))
                        if data.get('os') and not scan_data['os']:
                            scan_data['os'] = data['os']
                        scan_data['scan_files_used'].append(str(txt_file))
                        
                except Exception as e:
                    if self.debug:
                        print(f"    ⚠️  Error parsing {txt_file}: {e}")
                    continue
        
        # Convert sets to lists for JSON serialization
        scan_data['ports'] = sorted(list(scan_data['ports']))
        scan_data['hostnames'] = list(scan_data['hostnames'])
        
        return scan_data if scan_data['ports'] or scan_data['services'] else None
    
    def _parse_nmap_xml(self, xml_file: Path) -> Optional[Dict]:
        """Parse nmap XML files - old version's approach"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            data = {
                'ports': set(),
                'services': [],
                'os': None,
                'hostnames': []
            }
            
            # Extract ports and services
            for host in root.findall('.//host'):
                for port in host.findall('.//port'):
                    port_id = port.get('portid')
                    if port_id:
                        data['ports'].add(int(port_id))
                    
                    # Extract service info
                    service = port.find('service')
                    if service is not None:
                        service_name = service.get('name', '')
                        if service_name:
                            data['services'].append(service_name)
                
                # Extract OS info
                os_elem = host.find('.//os/osmatch')
                if os_elem is not None and not data['os']:
                    data['os'] = os_elem.get('name', '')
                
                # Extract hostnames
                for hostname in host.findall('.//hostname'):
                    name = hostname.get('name')
                    if name:
                        data['hostnames'].append(name)
            
            return data
            
        except Exception as e:
            if self.debug:
                print(f"Error parsing XML {xml_file}: {e}")
            return None
    
    def _parse_nmap_text(self, txt_file: Path) -> Optional[Dict]:
        """Parse nmap text files - old version's approach"""
        try:
            content = txt_file.read_text()
            
            data = {
                'ports': set(),
                'services': [],
                'os': None,
                'hostnames': []
            }
            
            # Extract open ports
            for line in content.split('\n'):
                line = line.strip()
                if '/tcp' in line and 'open' in line:
                    try:
                        port = int(line.split('/')[0])
                        data['ports'].add(port)
                        
                        # Extract service name
                        parts = line.split()
                        if len(parts) >= 3:
                            service = parts[2]
                            data['services'].append(service)
                    except (ValueError, IndexError):
                        continue
                
                # Extract OS info
                if 'OS:' in line or 'Running:' in line:
                    data['os'] = line.split(':', 1)[1].strip()
            
            return data
            
        except Exception as e:
            if self.debug:
                print(f"Error parsing text {txt_file}: {e}")
            return None
    
    def _display_enhanced_results(self, confidence_results: Dict, recommendations: Dict, 
                                scan_data: Dict, env: Dict):
        """Display results - old version's clean formatting"""
        
        # Environment classification with old version's visual approach
        if confidence_results:
            print("\n🎯 ENVIRONMENT CLASSIFICATION:")
            print("─" * 60)
            
            # Sort by confidence
            sorted_confidence = sorted(confidence_results.items(), 
                                     key=lambda x: x[1].confidence, 
                                     reverse=True)
            
            for env_type, result in sorted_confidence[:3]:
                confidence = result.confidence
                uncertainty = result.get('uncertainty', 0)
                
                # Create confidence bar - old version's approach
                bar_length = 8
                filled_length = int(bar_length * confidence / 100)
                conf_bar = "█" * filled_length + "░" * (bar_length - filled_length)
                
                env_display = env_type.replace('_', ' ').title()
                priority = "🔴" if confidence > 80 else "🟠" if confidence > 60 else "🟡"
                
                print(f"   {confidence:.1f}% (±{uncertainty:.1f}%) [{conf_bar}] {env_display} {priority}")
                print(f"   Evidence: {result.evidence_count} patterns | Method: {result.detection_method}")
                print()
        
        # Database-driven recommendations with old version's formatting
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
            
            # Show high priority techniques - old version's clean format
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
            
            # Show attack timeline - old version's format
            timeline = summary.get('attack_timeline', [])
            if timeline:
                print("⏱️ SUGGESTED ATTACK TIMELINE:")
                print("─" * 45)
                for phase in timeline:
                    phase_name = phase.get('phase_name', 'Unknown Phase')
                    estimated_time = phase.get('estimated_time', 'Unknown')
                    priority = phase.get('priority', 'medium')
                    
                    priority_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(priority, "🟡")
                    
                    print(f"Phase {phase.get('phase', 0)}: {phase_name} ({estimated_time}) {priority_icon}")
                    for technique in phase.get('techniques', []):
                        print(f"   → {technique}")
                    print()
            
            # Show recommended tools
            tools = summary.get('recommended_tools', [])
            if tools:
                print("🔧 RECOMMENDED TOOLS:")
                print("─" * 45)
                
                # Group tools by category for better display
                tool_categories = {
                    'Enumeration': ['nmap', 'gobuster', 'enum4linux', 'dirb', 'dirbuster'],
                    'Web Testing': ['burpsuite', 'sqlmap', 'nikto', 'wfuzz'],
                    'Exploitation': ['metasploit', 'exploit', 'nc', 'netcat'],
                    'Password Attacks': ['hydra', 'john', 'hashcat', 'crackmapexec'],
                    'Other': []
                }
                
                categorized_tools = {cat: [] for cat in tool_categories}
                
                for tool in tools[:10]:  # Limit display
                    categorized = False
                    for category, cat_tools in tool_categories.items():
                        if any(ct in tool.lower() for ct in cat_tools):
                            categorized_tools[category].append(tool)
                            categorized = True
                            break
                    if not categorized:
                        categorized_tools['Other'].append(tool)
                
                for category, cat_tools in categorized_tools.items():
                    if cat_tools:
                        print(f"   {category}: {', '.join(cat_tools)}")
    
    def _save_comprehensive_intelligence(self, env: Dict, confidence_results: Dict, 
                                       recommendations: Dict, scan_data: Dict) -> Path:
        """Save comprehensive intelligence data - keeping current method signature"""
        
        outdir = Path(env.get('OUTDIR', ''))
        boxname = env.get('BOXNAME', '')
        ip = env.get('IP', '')
        
        # Create intelligence directory
        intel_dir = outdir / "intelligence"
        intel_dir.mkdir(exist_ok=True)
        
        # Prepare comprehensive intelligence report - current structure
        intel_report = {
            'metadata': {
                'version': '3.0',
                'timestamp': datetime.now().isoformat(),
                'analysis_engine': 'JASMIN Enhanced Database-Driven Intelligence',
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
                if self.debug:
                    print(f"    ⚠️  Could not get database stats: {e}")
        
        # Save intelligence file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        intel_file = intel_dir / f"{boxname}_intelligence_{timestamp}.json"
        
        try:
            with open(intel_file, 'w') as f:
                json.dump(intel_report, f, indent=2, default=str)
            
            # Also save as latest
            latest_file = intel_dir / f"{boxname}_intelligence_latest.json"
            with open(latest_file, 'w') as f:
                json.dump(intel_report, f, indent=2, default=str)
            
            return intel_file
            
        except Exception as e:
            if self.debug:
                print(f"    ⚠️  Error saving intelligence file: {e}")
            return None
    
    def _update_jasmin_notes(self, env: Dict, confidence_results: Dict, 
                           recommendations: Dict, scan_data: Dict):
        """Update JASMIN notes with intelligence - old version's approach"""
        
        try:
            outdir = Path(env.get('OUTDIR', ''))
            boxname = env.get('BOXNAME', '')
            
            # Determine notes file path - compatible with current JASMIN structure
            if 'HOST' in env:
                host_ip = env['HOST']
                notes_file = outdir / f"{boxname}_{host_ip.replace('.', '_')}_notes.txt"
            else:
                notes_file = outdir / f"{boxname}_notes.txt"
            
            # Read existing notes
            notes_content = ""
            if notes_file.exists():
                notes_content = notes_file.read_text()
            
            # Check if intelligence section exists
            intelligence_section = f"\n[Intelligence Analysis - {datetime.now().strftime('%Y-%m-%d %H:%M')}]:\n"
            
            # Add environment classification
            if confidence_results:
                best_env = max(confidence_results.items(), key=lambda x: x[1].confidence)
                env_name = best_env[0].replace('_', ' ').title()
                confidence = best_env[1].confidence
                intelligence_section += f"Environment: {env_name} ({confidence:.1f}% confidence)\n"
            
            # Add top recommendations
            if recommendations and recommendations.get('high_priority'):
                intelligence_section += "Top Techniques:\n"
                for i, tech in enumerate(recommendations['high_priority'][:3], 1):
                    name = tech['technique_name']
                    success = tech.get('success_rate', 0)
                    intelligence_section += f"  {i}. {name} ({success:.1%} success)\n"
            
            # Add database stats
            if self.matcher:
                try:
                    stats = self.matcher.get_database_stats()
                    intelligence_section += f"Database: {stats.get('scenarios', 0)} scenarios, {stats.get('techniques', 0)} techniques\n"
                except Exception:
                    pass
            
            intelligence_section += "\n"
            
            # Append to notes
            with open(notes_file, 'a') as f:
                f.write(intelligence_section)
                
        except Exception as e:
            if self.debug:
                print(f"    ⚠️  Could not update notes: {e}")
    
    def get_intelligence_summary(self, env: Dict) -> Optional[Dict]:
        """Get intelligence summary for current target - keeping current method signature"""
        
        outdir = Path(env.get('OUTDIR', ''))
        boxname = env.get('BOXNAME', '')
        
        # Try to load latest intelligence file
        intel_file = outdir / "intelligence" / f"{boxname}_intelligence_latest.json"
        if intel_file.exists():
            try:
                with open(intel_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                if self.debug:
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
                    if self.debug:
                        print(f"[!] Failed to load intelligence file: {e}")
        
        return None
    
    def get_performance_stats(self) -> Dict:
        """Get performance statistics - keeping current method signature"""
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


# Global instance for integration - keeping current structure
_intelligence_integration = None

def init_intelligence_system():
    """Initialize the global intelligence system - keeping current function signature"""
    global _intelligence_integration
    if _intelligence_integration is None:
        _intelligence_integration = EnhancedIntelligenceIntegration()
    return _intelligence_integration

def auto_analyze_scan_results(env: Dict):
    """Auto-analyze scan results - keeping current function signature"""
    global _intelligence_integration
    if _intelligence_integration is None:
        _intelligence_integration = init_intelligence_system()
    
    _intelligence_integration.auto_analyze_scan_results(env)

def handle_intel_command(env: Dict, tokens: List[str]):
    """Enhanced intel command handler - keeping current signature and routing"""
    global _intelligence_integration
    
    # Check for debug flag
    debug_mode = '--debug' in tokens
    
    if _intelligence_integration is None:
        _intelligence_integration = EnhancedIntelligenceIntegration(debug=debug_mode)
    
    # Auto-detect session environment if not provided - old version's robust approach
    if not env:
        env = _auto_detect_session_environment()
    
    if not env or not all(key in env for key in ['BOXNAME', 'OUTDIR']):
        print("[!] No valid session found")
        print(f"[!] Current directory: {Path.cwd()}")
        print("[!] Try running from a box directory: cd ~/Boxes/Forest")
        return env
    
    # Show session info in debug mode only
    if debug_mode:
        boxname = env['BOXNAME']
        print(f"[+] Session: {boxname} ({env.get('IP', 'unknown')})")
    
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
            print(f"[!] Unknown intel command: {subcommand}")
            _show_intel_help()
            
    except Exception as e:
        print(f"[!] Intelligence command failed: {e}")
        if debug_mode:
            import traceback
            traceback.print_exc()
    
    return env

def _auto_detect_session_environment():
    """Auto-detect session from current directory - old version's approach"""
    current_dir = Path.cwd()
    
    # Walk up directory tree looking for session.env
    for check_dir in [current_dir] + list(current_dir.parents):
        session_file = check_dir / "session.env"
        if session_file.exists():
            env = {}
            try:
                with open(session_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if '=' in line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            env[key.strip()] = value.strip()
                
                if all(key in env for key in ['BOXNAME', 'OUTDIR']):
                    return env
            except Exception:
                pass
        
        # Stop at home directory
        if check_dir == Path.home():
            break
    
    return None

def _show_intel_help():
    """Show comprehensive intel command help - old version's format"""
    print("""
🧠 JASMIN Intelligence Commands:

  intel dashboard          Show intelligence overview for current target
  intel suggest           Get database-driven attack recommendations  
  intel analyze           Re-run intelligence analysis on scan results
  intel show port <n>     Deep analysis of specific port
  intel show service <n>  Analyze service attack techniques
  intel stats             Show system performance & database stats
  intel help              Show this help message
  
  Add --debug to any command for verbose output
""")

def _show_intelligence_dashboard(env: Dict):
    """Fixed dashboard section with safe formatting"""
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
    
    # FIXED: Safe target summary with None handling
    try:
        target = summary.get('target', {})
        name = target.get('name') or 'Unknown'
        ip = target.get('ip') or 'Unknown'
        ports = target.get('ports', [])
        services = target.get('services', [])
        os_info = target.get('os')
        
        print(f"🎯 Target: {name} ({ip})")
        print(f"📊 Ports: {len(ports)} | Services: {len(services)}")
        if os_info and os_info != 'None' and str(os_info).strip():
            print(f"💻 OS: {os_info}")
        
    except Exception as e:
        print(f"🎯 Target display error: {e}")
    
    # FIXED: Safe database statistics
    try:
        db_stats = summary.get('database_stats', {})
        if db_stats:
            scenarios = db_stats.get('scenarios', 0) or 0
            techniques = db_stats.get('techniques', 0) or 0
            port_mappings = db_stats.get('port_mappings', 0) or 0
            service_mappings = db_stats.get('service_mappings', 0) or 0
            
            print(f"\n📚 Database Coverage:")
            print(f"   Scenarios: {scenarios:,}")
            print(f"   Techniques: {techniques:,}")
            print(f"   Port Mappings: {port_mappings:,}")
            print(f"   Service Mappings: {service_mappings:,}")
    
    except Exception as e:
        print(f"📚 Database stats error: {e}")
    
    # FIXED: Safe recommendations summary
    try:
        recommendations = summary.get('recommendations', {})
        if recommendations:
            summary_stats = recommendations.get('summary', {})
            high_priority = recommendations.get('high_priority', [])
            medium_priority = recommendations.get('medium_priority', [])
            tools = summary_stats.get('recommended_tools', [])
            
            total_techniques = summary_stats.get('total_techniques', 0) or 0
            source_scenarios = summary_stats.get('source_scenarios', 0) or 0
            
            print(f"\n🎯 ATTACK RECOMMENDATIONS:")
            print(f"   • Total Techniques: {total_techniques}")
            print(f"   • Source Scenarios: {source_scenarios}")
            print(f"   • High Priority: {len(high_priority)}")
            print(f"   • Medium Priority: {len(medium_priority)}")
            print(f"   • Recommended Tools: {len(tools) if tools else 0}")
    
    except Exception as e:
        print(f"🎯 Recommendations error: {e}")
    
    # FIXED: Safe metadata display
    try:
        metadata = summary.get('metadata', {})
        if metadata:
            version = metadata.get('version') or 'Unknown'
            print(f"\n📊 Analysis Metadata:")
            print(f"   • Version: {version}")
    
    except Exception as e:
        print(f"📊 Metadata error: {e}")


# Fix 3: Add this safe formatting helper function to intelligence_integration.py:

def _safe_format(value, default="Unknown"):
    """Safely format values that might be None"""
    if value is None:
        return default
    if isinstance(value, str) and value.strip() == '':
        return default
    return str(value)

def _show_attack_suggestions(env: Dict):
    """Enhanced attack suggestions - old version's formatting with current variables"""
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
    
    print(f"📋 Target: {target.get('name')} ({target.get('ip')})")
    
    # Show database statistics
    db_stats = summary.get('database_stats', {})
    if db_stats:
        print(f"📚 Intelligence Source: {db_stats.get('scenarios', 0)} scenarios, {db_stats.get('techniques', 0)} techniques")
    
    if not recommendations:
        print("⚠️  No recommendations available")
        return
    
    # HIGH PRIORITY - old version's clean formatting
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
            print(f"   Tools: {', '.join(tools[:2])}")
            
            # Show example commands - old version's safe approach
            commands = tech.get('example_commands', [])
            if commands:
                try:
                    if isinstance(commands[0], dict):
                        cmd = commands[0].get('command', str(commands[0]))
                    else:
                        cmd = str(commands[0])
                    print(f"   Example: {cmd}")
                except Exception:
                    pass
            print()
    
    # MEDIUM PRIORITY
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
    
    # ATTACK TIMELINE - old version's format
    summary_data = recommendations.get('summary', {})
    timeline = summary_data.get('attack_timeline', [])
    if timeline:
        print(f"\n⏱ SUGGESTED ATTACK TIMELINE:")
        print("─" * 45)
        for phase in timeline:
            phase_name = phase.get('phase_name', 'Unknown Phase')
            estimated_time = phase.get('estimated_time', 'Unknown')
            priority = phase.get('priority', 'medium')
            
            priority_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(priority, "🟡")
            
            print(f"Phase {phase.get('phase', 0)}: {phase_name} ({estimated_time}) {priority_icon}")
            for technique in phase.get('techniques', []):
                print(f"   → {technique}")
            print()
    
    # RECOMMENDED TOOLS
    tools = summary_data.get('recommended_tools', [])
    if tools:
        print(f"🔧 RECOMMENDED TOOLS:")
        print("─" * 45)
        
        # Group tools by type for better display
        tool_groups = {
            'Enumeration': [],
            'Web Testing': [],
            'Other': []
        }
        
        enum_tools = ['nmap', 'gobuster', 'enum4linux', 'dirb', 'dirbuster', 'netexec', 'crackmapexec']
        web_tools = ['burpsuite', 'sqlmap', 'nikto', 'wfuzz']
        
        for tool in tools[:10]:  # Limit display
            if any(et in tool.lower() for et in enum_tools):
                tool_groups['Enumeration'].append(tool)
            elif any(wt in tool.lower() for wt in web_tools):
                tool_groups['Web Testing'].append(tool)
            else:
                tool_groups['Other'].append(tool)
        
        for group, group_tools in tool_groups.items():
            if group_tools:
                print(f"   {group}: {', '.join(group_tools)}")

def _show_detailed_analysis(env: Dict, args: List[str]):
    """Show detailed analysis - old version's approach"""
    if len(args) < 2:
        print("Usage: intel show <port|service> <value>")
        return
    
    analysis_type = args[0].lower()
    value = args[1]
    
    if analysis_type == "port":
        try:
            port = int(value)
            _show_port_analysis(env, port)
        except ValueError:
            print(f"[!] Invalid port number: {value}")
    elif analysis_type == "service":
        _show_service_analysis(env, value)
    else:
        print("Usage: intel show <port|service> <value>")

def _show_port_analysis(env: Dict, port: int):
    """Show detailed port analysis - old version's formatting"""
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
                print(f"   Tools: {', '.join(tools[:3])}")
                
                # Show description if available
                description = tech.get('description', '')
                if description:
                    print(f"   Description: {description}")
                
                # Show example commands safely
                commands = tech.get('example_commands', [])
                if commands:
                    try:
                        if isinstance(commands[0], dict):
                            cmd = commands[0].get('command', str(commands[0]))
                        else:
                            cmd = str(commands[0])
                        print(f"   Example: {cmd}")
                    except Exception:
                        pass
                print()
        
        else:
            print(f"⚠️  No specific techniques found for port {port}")
            print(f"💡 Port {port} may not be well-covered in the database")
    
    except Exception as e:
        print(f"❌ Error analyzing port {port}: {e}")

def _show_service_analysis(env: Dict, service: str):
    """Show detailed service analysis - old version's formatting"""
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
                print(f"   Tools: {', '.join(tools[:3])}")
                print()
        
        else:
            print(f"⚠️  No specific techniques found for service {service}")
            print(f"💡 Service {service} may not be well-covered in the database")
    
    except Exception as e:
        print(f"❌ Error analyzing service {service}: {e}")

def _show_performance_stats():
    """Show performance statistics - old version's formatting"""
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
        except Exception as e:
            print(f"  Database stats unavailable: {e}")