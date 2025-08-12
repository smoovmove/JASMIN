#!/usr/bin/env python3

"""
Enhanced Intelligence Matcher - Database-Driven Implementation
Uses old version's robust approach with current variable names and database structure
"""

import json
import re
import sqlite3
from pathlib import Path 
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from datetime import datetime

@dataclass
class DatabaseTechnique:
    """Technique loaded from intelligence database - keeping current structure"""
    name: str
    success_rate: float
    complexity: str
    tools: List[str]
    description: str
    example_commands: List[str]
    mitre_id: str = ""
    category: str = ""
    time_estimate: str = ""
    prerequisites: List[str] = None
    success_indicators: List[str] = None
    scenario_count: int = 0
    confidence_score: float = 0.0

@dataclass
class DatabaseScenario:
    """Scenario loaded from intelligence database - keeping current structure"""
    id: int
    scenario_name: str
    canonical_name: str
    port_signature: str
    service_combination: str
    os_family: str
    environment_type: str
    attack_complexity: str
    confidence_score: float
    writeup_count: int
    techniques: List[str] = None
    expected_time: str = ""

class EnhancedIntelligenceMatcher:
    """Database-driven intelligence matcher - old version's robustness + current variables"""
    
    def __init__(self, db_path: str = "/home/saint/Documents/Jasmin/intelligence.db", debug=False):
        """Initialize with database path - keeping current signature"""
        self.db_path = db_path
        self.conn = None
        self.cache = {}
        self.port_technique_cache = {}
        self.service_technique_cache = {}
        self.debug = debug
        
        # Initialize database connection with old version's robust approach
        self._initialize_database()
        
        # Load cached data for performance
        if self.conn:
            self._load_technique_cache()
            self._load_port_service_mappings()
    
    def _initialize_database(self):
        """Initialize database connection - old version's robust error handling"""
        try:
            if Path(self.db_path).exists():
                self.conn = sqlite3.connect(self.db_path)
                self.conn.row_factory = sqlite3.Row
                
                if self.debug:
                    print(f"[+] Connected to intelligence database: {self.db_path}")
                
                # Verify database structure with old version's approach
                self._verify_database_structure()
            else:
                if self.debug:
                    print(f"[!] Intelligence database not found: {self.db_path}")
                    print("[!] Falling back to basic recommendations")
                
        except Exception as e:
            if self.debug:
                print(f"[!] Database connection failed: {e}")
                print("[!] Falling back to basic recommendations")
            self.conn = None
    
    def _verify_database_structure(self):
        """Verify database has required tables - old version's approach"""
        required_tables = ['scenarios', 'techniques', 'port_mappings', 'service_mappings']
        
        for table in required_tables:
            try:
                result = self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
                count = result[0]
                if self.debug:
                    print(f"   ✓ {table}: {count} records")
            except sqlite3.OperationalError:
                if self.debug:
                    print(f"   ✗ {table}: Missing")
    
    def _load_technique_cache(self):
        """Load techniques into cache - FIXED with proper scenario counting"""
        if not self.conn:
            return
        
        try:
            # FIXED: Proper technique counting from old version approach
            techniques = self.conn.execute("""
                SELECT t.name, 
                       AVG(t.success_rate) as success_rate,
                       t.difficulty, 
                       t.time_estimate, 
                       t.category, 
                       t.mitre_id,
                       COUNT(DISTINCT t.scenario_id) as scenario_count,
                       GROUP_CONCAT(DISTINCT t.data_json) as data_json_list
                FROM techniques t
                GROUP BY t.name
                ORDER BY AVG(t.success_rate) DESC, scenario_count DESC
            """).fetchall()
            
            for tech in techniques:
                try:
                    # Parse the JSON data safely - old version's approach
                    tech_data = {}
                    if tech['data_json_list']:
                        try:
                            # Take first non-null JSON data
                            json_list = [j for j in tech['data_json_list'].split(',') if j and j != 'null']
                            if json_list:
                                tech_data = json.loads(json_list[0])
                        except (json.JSONDecodeError, Exception):
                            tech_data = {}
                    
                    # Extract data safely with old version's robust approach
                    tool_list = self._extract_tools_list(tech_data.get('tools', []))
                    commands = self._extract_commands_list(tech_data.get('commands', []))
                    
                    # Create DatabaseTechnique with old version's safe defaults
                    db_technique = DatabaseTechnique(
                        name=tech['name'] or 'Unknown Technique',
                        success_rate=tech['success_rate'] or 0.8,  # Safe default
                        complexity=tech['difficulty'] or 'medium',
                        tools=tool_list,
                        description=tech_data.get('description', ''),
                        example_commands=commands,
                        mitre_id=tech['mitre_id'] or '',
                        category=tech['category'] or 'unknown',
                        time_estimate=tech['time_estimate'] or '5-15 minutes',
                        scenario_count=tech['scenario_count'] or 1,  # FIXED: Now shows real count
                        confidence_score=tech_data.get('confidence_score', 0.8)
                    )
                    
                    self.cache[tech['name']] = db_technique
                    
                except Exception as e:
                    if self.debug:
                        print(f"[!] Error processing technique {tech['name']}: {e}")
                    continue
            
            if self.debug:
                print(f"✓ Loaded {len(self.cache)} techniques into cache")
                
        except Exception as e:
            if self.debug:
                print(f"[!] Error loading technique cache: {e}")

    def _extract_tools_list(self, tools_data: Any) -> List[str]:
        """Extract tools list ensuring consistent string format - FROM OLD WORKING VERSION"""
        if not tools_data:
            return []
        
        tools = []
        if isinstance(tools_data, list):
            for tool in tools_data:
                if isinstance(tool, dict):
                    # Extract tool name from dict
                    tool_name = tool.get('name', tool.get('tool', str(tool)))
                    tools.append(str(tool_name))
                else:
                    tools.append(str(tool))
        elif isinstance(tools_data, str):
            # Split comma-separated tools
            tools = [t.strip() for t in tools_data.split(',') if t.strip()]
        else:
            tools = [str(tools_data)]
        
        return tools

    def _extract_commands_list(self, commands_data: Any) -> List[str]:
        """Extract commands list ensuring consistent string format - FROM OLD WORKING VERSION"""
        if not commands_data:
            return []
        
        commands = []
        if isinstance(commands_data, list):
            for cmd in commands_data:
                if isinstance(cmd, dict):
                    # Extract command from dict
                    command = cmd.get('command', cmd.get('cmd', str(cmd)))
                    commands.append(str(command))
                else:
                    commands.append(str(cmd))
        elif isinstance(commands_data, str):
            commands = [commands_data]
        else:
            commands = [str(commands_data)]
        
        return commands
    
    def _load_port_service_mappings(self):
        """Load port and service mappings - FIXED SCHEMA"""
        if not self.conn:
            return
        
        try:
            # FIXED: Load port mappings with correct schema
            port_mappings = self.conn.execute("""
                SELECT DISTINCT 
                    pm.port,
                    t.name as technique_name,
                    t.success_rate,
                    t.difficulty,
                    COUNT(DISTINCT s.id) as frequency
                FROM port_mappings pm
                JOIN scenarios s ON pm.scenario_id = s.id
                JOIN techniques t ON t.scenario_id = s.id
                WHERE pm.port IS NOT NULL AND t.name IS NOT NULL
                GROUP BY pm.port, t.name
                ORDER BY pm.port, t.success_rate DESC
            """).fetchall()
            
            for mapping in port_mappings:
                port = mapping['port']
                if port not in self.port_technique_cache:
                    self.port_technique_cache[port] = []
                
                self.port_technique_cache[port].append({
                    'technique': mapping['technique_name'],
                    'weight': mapping['success_rate'] or 0.8,
                    'success_rate': mapping['success_rate'] or 0.8,
                    'frequency': mapping['frequency'] or 1
                })
            
            # FIXED: Load service mappings with correct schema
            service_mappings = self.conn.execute("""
                SELECT DISTINCT 
                    sm.service,
                    t.name as technique_name,
                    t.success_rate,
                    t.difficulty,
                    COUNT(DISTINCT s.id) as frequency
                FROM service_mappings sm
                JOIN scenarios s ON sm.scenario_id = s.id
                JOIN techniques t ON t.scenario_id = s.id
                WHERE sm.service IS NOT NULL AND t.name IS NOT NULL
                GROUP BY sm.service, t.name
                ORDER BY sm.service, t.success_rate DESC
            """).fetchall()
            
            for mapping in service_mappings:
                service = mapping['service']
                if service not in self.service_technique_cache:
                    self.service_technique_cache[service] = []
                
                self.service_technique_cache[service].append({
                    'technique': mapping['technique_name'],
                    'weight': mapping['success_rate'] or 0.8,
                    'success_rate': mapping['success_rate'] or 0.8,
                    'frequency': mapping['frequency'] or 1
                })
            
            if self.debug:
                print(f"[+] Loaded mappings: {len(self.port_technique_cache)} ports, {len(self.service_technique_cache)} services")
        
        except Exception as e:
            if self.debug:
                print(f"[!] Error loading port/service mappings: {e}")
    
    def get_port_specific_techniques(self, ports: List[int], limit: int = 10) -> List[Dict]:
        """Get techniques specific to open ports - old version's robust approach"""
        
        if not self.conn:
            return self._get_fallback_port_techniques(ports)
        
        techniques = []
        technique_scores = defaultdict(lambda: {'score': 0, 'sources': [], 'frequency': 0})
        
        # Score techniques based on port presence - old version's logic
        for port in ports:
            if port in self.port_technique_cache:
                for mapping in self.port_technique_cache[port]:
                    tech_name = mapping['technique']
                    weight = mapping['weight']
                    success_rate = mapping['success_rate']
                    
                    # Enhanced scoring with old version's approach
                    base_score = (weight * 0.7) + (success_rate * 0.3)
                    port_boost = self._get_port_boost(port)
                    final_score = base_score * port_boost
                    
                    technique_scores[tech_name]['score'] += final_score
                    technique_scores[tech_name]['sources'].append(f"port_{port}")
                    technique_scores[tech_name]['frequency'] += 1
        
        # Get top techniques and enrich with database data - old version's approach
        sorted_techniques = sorted(
            technique_scores.items(), 
            key=lambda x: (x[1]['score'], x[1]['frequency']), 
            reverse=True
        )[:limit]
        
        for tech_name, score_data in sorted_techniques:
            if tech_name in self.cache:
                technique = self.cache[tech_name]
                
                # Use old version's clean formatting
                tech_dict = {
                    'technique_name': technique.name,
                    'success_rate': self._calculate_realistic_success_rate(technique),
                    'complexity': technique.complexity,
                    'primary_tools': technique.tools[:3],  # Top 3 tools
                    'description': technique.description,
                    'example_commands': technique.example_commands[:3],  # Top 3 commands
                    'mitre_id': technique.mitre_id,
                    'category': technique.category,
                    'time_estimate': technique.time_estimate,
                    'scenario_count': technique.scenario_count,  # FIXED: Now correct
                    'confidence_score': technique.confidence_score,
                    'matching_sources': score_data['sources'],
                    'frequency': score_data['frequency'],
                    'composite_score': score_data['score']
                }
                
                techniques.append(tech_dict)
        
        return techniques
    
    def get_service_specific_techniques(self, services: List[str], limit: int = 10) -> List[Dict]:
        """Get techniques specific to services from database - FIXED SCHEMA"""
        
        if not self.conn:
            return self._get_fallback_service_techniques(services)
        
        techniques = []
        technique_scores = defaultdict(lambda: {'score': 0, 'sources': [], 'frequency': 0})
        
        # FIXED: Direct database query with correct schema
        try:
            for service in services:
                # FIXED: Use correct column names and table structure
                query = """
                SELECT DISTINCT 
                    t.name,
                    t.success_rate,
                    t.difficulty,
                    t.data_json,
                    t.category,
                    t.mitre_id,
                    t.time_estimate,
                    COUNT(DISTINCT s.id) as scenario_count
                FROM techniques t
                JOIN scenarios s ON t.scenario_id = s.id
                JOIN service_mappings sm ON sm.scenario_id = s.id
                WHERE sm.service LIKE ? OR s.service_combination LIKE ?
                GROUP BY t.name, t.success_rate, t.difficulty, t.data_json
                ORDER BY t.success_rate DESC, scenario_count DESC
                LIMIT ?
                """
                
                cursor = self.conn.execute(query, [f'%{service}%', f'%{service}%', limit])
                results = cursor.fetchall()
                
                for row in results:
                    tech_name = row['name']
                    success_rate = row['success_rate'] or 0.8
                    scenario_count = row['scenario_count']
                    
                    # Calculate score based on success rate and frequency
                    base_score = success_rate * 0.7
                    frequency_bonus = min(scenario_count / 50, 0.3)
                    final_score = base_score + frequency_bonus
                    
                    if tech_name not in technique_scores or technique_scores[tech_name]['score'] < final_score:
                        # FIXED: Parse tools from JSON data
                        tools = []
                        commands = []
                        if row['data_json']:
                            try:
                                data = json.loads(row['data_json'])
                                # Extract tools from JSON
                                if 'tools' in data and isinstance(data['tools'], list):
                                    for tool in data['tools']:
                                        if isinstance(tool, dict):
                                            tool_name = tool.get('name', '')
                                            if tool_name:
                                                tools.append(tool_name)
                                        elif tool:
                                            tools.append(str(tool))
                                
                                # Extract commands from JSON
                                if 'commands' in data and isinstance(data['commands'], list):
                                    commands = [str(cmd) for cmd in data['commands'][:3]]
                            except (json.JSONDecodeError, TypeError):
                                pass
                        
                        technique_scores[tech_name] = {
                            'score': final_score,
                            'sources': [f"service_{service}"],
                            'frequency': scenario_count,
                            'data': {
                                'technique_name': tech_name,
                                'success_rate': success_rate,
                                'complexity': row['difficulty'] or 'medium',
                                'primary_tools': tools,
                                'example_commands': commands,
                                'category': row['category'] or 'unknown',
                                'mitre_id': row['mitre_id'] or '',
                                'time_estimate': row['time_estimate'] or '5-15 minutes',
                                'scenario_count': scenario_count,
                                'composite_score': final_score
                            }
                        }
        
        except Exception as e:
            if self.debug:
                print(f"[!] Service technique query failed: {e}")
            return self._get_fallback_service_techniques(services)
        
        # Sort and return techniques
        sorted_techniques = sorted(
            technique_scores.items(),
            key=lambda x: (x[1]['score'], x[1]['frequency']),
            reverse=True
        )[:limit]
        
        for tech_name, score_data in sorted_techniques:
            tech_dict = score_data['data']
            tech_dict['matching_sources'] = score_data['sources']
            techniques.append(tech_dict)
        
        return techniques
    
    def get_database_optimized_recommendations(self, ports: List[int], services: List[str], 
                                             env_type: str = None, os_detected: str = None) -> Dict:
        """Get optimized recommendations - FIXED TOOLS EXTRACTION"""
        
        if self.debug:
            print(f"🧠 Analyzing based on {len(ports)} ports and {len(services)} services")
            print(f"📊 Drawing from database")
        
        # Initialize recommendations structure - keeping current variable names
        recommendations = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': [],
            'summary': {
                'total_techniques': 0,
                'source_scenarios': 0,
                'technique_diversity': 0,
                'data_confidence': 'medium',
                'recommended_tools': set(),
                'attack_timeline': []
            }
        }
        
        # Get techniques from ports and services
        all_techniques = []
        
        # Port-based techniques
        if ports:
            port_techniques = self.get_port_specific_techniques(ports, limit=20)
            all_techniques.extend(port_techniques)
        
        # Service-based techniques
        if services:
            service_techniques = self.get_service_specific_techniques(services, limit=20)
            all_techniques.extend(service_techniques)
        
        # Remove duplicates and sort by composite score
        unique_techniques = {}
        for tech in all_techniques:
            tech_name = tech['technique_name']
            if tech_name not in unique_techniques or tech['composite_score'] > unique_techniques[tech_name]['composite_score']:
                unique_techniques[tech_name] = tech
        
        sorted_techniques = sorted(
            unique_techniques.values(),
            key=lambda x: x.get('composite_score', 0),
            reverse=True
        )
        
        # FIXED: Categorize by priority AND preserve tools data
        for tech in sorted_techniques:
            priority = self._determine_priority(tech, ports, services, env_type)
            
            # CRITICAL FIX: Ensure tools are preserved in the technique data
            if 'primary_tools' not in tech:
                tech['primary_tools'] = []
            
            # CRITICAL FIX: Debug tools to see what's happening
            if self.debug and tech.get('primary_tools'):
                print(f"[DEBUG] {tech['technique_name']} has tools: {tech['primary_tools']}")
            
            recommendations[priority].append(tech)
        
        # FIXED: Collect tools properly from all techniques
        all_tools = set()
        for tech in sorted_techniques:
            tools = tech.get('primary_tools', [])
            if tools:
                if isinstance(tools, list):
                    all_tools.update(str(tool) for tool in tools if tool)
                elif tools:
                    all_tools.add(str(tools))
        
        # Update summary statistics
        total_techniques = len(sorted_techniques)
        recommendations['summary']['total_techniques'] = total_techniques
        recommendations['summary']['source_scenarios'] = sum(
            t.get('scenario_count', 0) for t in sorted_techniques
        )
        recommendations['summary']['technique_diversity'] = len(
            set(t.get('category', 'unknown') for t in sorted_techniques)
        )
        recommendations['summary']['recommended_tools'] = list(all_tools)
        
        # Create optimized attack timeline
        recommendations['summary']['attack_timeline'] = self._create_optimized_timeline(
            sorted_techniques[:15]
        )
        
        # FIXED: Debug output to verify tools are present
        if self.debug:
            print(f"[DEBUG] Final summary tools: {len(recommendations['summary']['recommended_tools'])}")
            for priority in ['high_priority', 'medium_priority']:
                for tech in recommendations[priority][:2]:  # Check first 2 in each priority
                    tools = tech.get('primary_tools', [])
                    print(f"[DEBUG] {tech['technique_name']}: {len(tools)} tools - {tools}")
        
        return recommendations
    
    # Add these methods to your intelligence_matcher.py class:

    def _determine_priority(self, technique: Dict, ports: List[int], 
                                   services: List[str], env_type: str = None) -> str:
        """Determine technique priority using enhanced scoring logic"""
        try:
            composite_score = technique.get('composite_score', 0)
            success_rate = technique.get('success_rate', 0)
            scenario_count = technique.get('scenario_count', 0)
            
            # High priority criteria
            if (composite_score > 0.85 or 
                success_rate > 0.9 or
                scenario_count > 15):
                return 'high_priority'
            
            # Medium priority criteria
            elif (composite_score > 0.6 or 
                  success_rate > 0.75 or
                  scenario_count > 5):
                return 'medium_priority'
            
            # Low priority (everything else)
            else:
                return 'low_priority'
                
        except Exception as e:
            if self.debug:
                print(f"[!] Error determining priority: {e}")
            return 'low_priority'
    
    def _create_optimized_timeline(self, techniques: List[Dict]) -> List[Dict]:
        """Create attack timeline - old version's approach"""
        
        timeline = []
        
        # Phase 1: Reconnaissance
        recon_techniques = [t for t in techniques if 'enumeration' in t.get('technique_name', '').lower() or 'reconnaissance' in t.get('technique_name', '').lower()]
        if recon_techniques:
            timeline.append({
                'phase': 1,
                'phase_name': 'Reconnaissance',
                'estimated_time': '15-30 minutes',
                'priority': 'critical',
                'techniques': [t['technique_name'] for t in recon_techniques[:3]]
            })
        
        # Phase 2: Initial Access
        access_techniques = [t for t in techniques if 'exploit' in t.get('technique_name', '').lower() or 'injection' in t.get('technique_name', '').lower()]
        if access_techniques:
            timeline.append({
                'phase': 2,
                'phase_name': 'Initial Access',
                'estimated_time': '20-45 minutes',
                'priority': 'high',
                'techniques': [t['technique_name'] for t in access_techniques[:3]]
            })
        
        # Phase 3: Privilege Escalation
        privesc_techniques = [t for t in techniques if 'escalation' in t.get('technique_name', '').lower() or 'privilege' in t.get('technique_name', '').lower()]
        if privesc_techniques:
            timeline.append({
                'phase': 3,
                'phase_name': 'Privilege Escalation',
                'estimated_time': '15-30 minutes',
                'priority': 'medium',
                'techniques': [t['technique_name'] for t in privesc_techniques[:3]]
            })
        
        return timeline
    
    def _get_port_boost(self, port: int) -> float:
        """Get port-specific boost factor - old version's values"""
        port_boosts = {
            22: 1.2,    # SSH - high value
            80: 1.3,    # HTTP - very common
            443: 1.3,   # HTTPS - very common
            445: 1.4,   # SMB - high value
            3389: 1.2,  # RDP - high value
            88: 1.5,    # Kerberos - critical for AD
            389: 1.4,   # LDAP - critical for AD
            1433: 1.1,  # MSSQL
            3306: 1.1,  # MySQL
            5432: 1.1,  # PostgreSQL
            25: 0.9,    # SMTP
            
            # Specialized services
            5985: 1.2,  # WinRM
            5986: 1.2,  # WinRM SSL
            135: 1.1,   # RPC
            139: 1.1,   # NetBIOS
        }
        
        return port_boosts.get(port, 1.0)
    
    def _calculate_realistic_success_rate(self, technique: DatabaseTechnique) -> float:
        """Calculate realistic success rate - old version's logic"""
        
        base_rate = 0.85  # From database
        
        # Adjust based on complexity
        complexity_adjustments = {
            'trivial': 0.1,     # 95% success
            'easy': 0.05,       # 90% success  
            'beginner': 0.0,    # 85% success (baseline)
            'medium': -0.1,     # 75% success
            'hard': -0.2,       # 65% success
            'insane': -0.3,     # 55% success
            'very_hard': -0.25  # 60% success
        }
        
        complexity_adj = complexity_adjustments.get(technique.complexity.lower(), 0.0)
        
        # Adjust based on frequency
        frequency_adj = 0.0
        if technique.scenario_count > 50:
            frequency_adj = 0.05  # Very common technique
        elif technique.scenario_count > 20:
            frequency_adj = 0.02  # Common technique
        elif technique.scenario_count < 5:
            frequency_adj = -0.05  # Rare technique
        
        # Calculate final success rate
        final_rate = base_rate + complexity_adj + frequency_adj
        
        # Clamp between 0.3 and 0.95
        return max(0.3, min(0.95, final_rate))
    
    def get_database_stats(self) -> Dict[str, int]:
        """Get database statistics - FIXED SCHEMA"""
        stats = {
            'scenarios': 0,
            'techniques': 0,
            'port_mappings': 0,
            'service_mappings': 0,
            'cached_techniques': len(self.cache)
        }
        
        if not self.conn:
            return stats
        
        try:
            # FIXED: Use correct table names
            stats['scenarios'] = self.conn.execute("SELECT COUNT(*) FROM scenarios").fetchone()[0]
            stats['techniques'] = self.conn.execute("SELECT COUNT(DISTINCT name) FROM techniques").fetchone()[0]
            stats['port_mappings'] = self.conn.execute("SELECT COUNT(*) FROM port_mappings").fetchone()[0]
            stats['service_mappings'] = self.conn.execute("SELECT COUNT(*) FROM service_mappings").fetchone()[0]
        except Exception as e:
            if self.debug:
                print(f"[!] Error getting database stats: {e}")
        
        return stats
    
    def _get_fallback_port_techniques(self, ports: List[int]) -> List[Dict]:
        """Fallback recommendations when database unavailable - old version's approach"""
        fallback_techniques = []
        
        # Basic port-based fallbacks
        if 22 in ports:
            fallback_techniques.append({
                'technique_name': 'SSH Authentication Testing',
                'success_rate': 0.7,
                'complexity': 'beginner',
                'primary_tools': ['hydra', 'ncrack'],
                'scenario_count': 1,
                'description': 'Test for weak SSH credentials'
            })
        
        if 80 in ports or 443 in ports:
            fallback_techniques.append({
                'technique_name': 'Web Directory Enumeration',
                'success_rate': 0.8,
                'complexity': 'beginner',
                'primary_tools': ['gobuster', 'dirb'],
                'scenario_count': 1,
                'description': 'Enumerate web directories and files'
            })
        
        if 445 in ports:
            fallback_techniques.append({
                'technique_name': 'SMB Share Enumeration',
                'success_rate': 0.8,
                'complexity': 'beginner',
                'primary_tools': ['smbclient', 'enum4linux'],
                'scenario_count': 1,
                'description': 'Enumerate SMB shares and permissions'
            })
        
        return fallback_techniques
    
    def _get_fallback_service_techniques(self, services: List[str]) -> List[Dict]:
        """Fallback service recommendations - old version's approach"""
        return [
            {
                'technique_name': 'Service Version Detection',
                'success_rate': 0.8,
                'complexity': 'beginner',
                'primary_tools': ['nmap'],
                'scenario_count': 1,
                'description': 'Detect service versions for vulnerability research'
            }
        ]