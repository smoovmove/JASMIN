import json
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import re
import math

@dataclass
class ScenarioFingerprint:
    """Structured scenario fingerprint for fast matching"""
    scenario_name: str
    canonical_name: str
    port_signature: str
    service_combination: str
    os_family: str
    environment_type: str
    entry_vector: str
    attack_complexity: str
    confidence_score: float
    writeup_count: int
    success_indicators: List[str]
    distinguishing_factors: List[str]

@dataclass
class AttackTechnique:
    """Structured attack technique with actionable details"""
    name: str
    mitre_id: str
    category: str
    tools: List[Dict]
    commands: List[str]
    success_rate: float
    prerequisites: List[str]
    success_indicators: List[str]
    time_estimate: str
    difficulty: str

@dataclass
class ScenarioMatch:
    """Result of scenario matching with confidence scoring"""
    scenario: str
    canonical_name: str
    confidence: float
    matching_factors: List[str]
    recommended_techniques: List[str]
    writeup_examples: List[str]
    expected_time: str

class IntelligenceDatabase:
    """High-performance intelligence database with multi-layered indexes"""
    
    def __init__(self, db_path: str = "intelligence_db"):
        self.db_path = Path(db_path)
        self.conn = None
        self.indexes = {}
        self.scenario_fingerprints = {}
        self.technique_library = {}
        self.decision_trees = {}
        self.similarity_matrix = {}
        self.canonical_mapping = {}
        
        # Initialize database
        self._init_database()
        
    def _init_database(self):
        """Initialize SQLite database with optimized schema"""
        
        db_file = self.db_path / "intelligence.db"
        self.conn = sqlite3.connect(str(db_file))
        self.conn.row_factory = sqlite3.Row
        
        # Create optimized tables
        self.conn.executescript("""
            -- Scenario fingerprints table
            CREATE TABLE IF NOT EXISTS scenarios (
                id INTEGER PRIMARY KEY,
                scenario_name TEXT UNIQUE,
                canonical_name TEXT,
                port_signature TEXT,
                service_combination TEXT,
                os_family TEXT,
                environment_type TEXT,
                entry_vector TEXT,
                attack_complexity TEXT,
                confidence_score REAL,
                writeup_count INTEGER,
                data_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Attack techniques table
            CREATE TABLE IF NOT EXISTS techniques (
                id INTEGER PRIMARY KEY,
                name TEXT,
                mitre_id TEXT,
                category TEXT,
                success_rate REAL,
                difficulty TEXT,
                time_estimate TEXT,
                scenario_id INTEGER,
                data_json TEXT,
                FOREIGN KEY (scenario_id) REFERENCES scenarios (id)
            );
            
            -- Port-to-scenario mapping for fast lookup
            CREATE TABLE IF NOT EXISTS port_mappings (
                port INTEGER,
                protocol TEXT,
                scenario_id INTEGER,
                weight REAL,
                FOREIGN KEY (scenario_id) REFERENCES scenarios (id)
            );
            
            -- Service-to-scenario mapping
            CREATE TABLE IF NOT EXISTS service_mappings (
                service_name TEXT,
                scenario_id INTEGER,
                weight REAL,
                FOREIGN KEY (scenario_id) REFERENCES scenarios (id)
            );
            
            -- Environment detection rules
            CREATE TABLE IF NOT EXISTS environment_rules (
                environment_type TEXT,
                detection_rule TEXT,
                confidence_threshold REAL,
                scenario_count INTEGER
            );
            
            -- Create indexes for lightning-fast lookups
            CREATE INDEX IF NOT EXISTS idx_port_lookup ON port_mappings (port, protocol);
            CREATE INDEX IF NOT EXISTS idx_service_lookup ON service_mappings (service_name);
            CREATE INDEX IF NOT EXISTS idx_os_env ON scenarios (os_family, environment_type);
            CREATE INDEX IF NOT EXISTS idx_complexity ON scenarios (attack_complexity);
            CREATE INDEX IF NOT EXISTS idx_canonical ON scenarios (canonical_name);
            CREATE INDEX IF NOT EXISTS idx_ports ON scenarios (port_signature);
        """)
        
        self.conn.commit()
        print(f"✅ Database initialized at {db_file}")
    
    def build_from_intelligence_files(self, intelligence_dir: str, mapping_file: str = None):
        """Build database from intelligence extraction files"""
        
        print(f"🔄 Building intelligence database from {intelligence_dir}")
        intelligence_path = Path(intelligence_dir)
        
        # Load canonical mapping if provided
        if mapping_file and Path(mapping_file).exists():
            with open(mapping_file, 'r') as f:
                mapping_data = json.load(f)
                self.canonical_mapping = mapping_data.get('scenario_name_mapping', {})
                print(f"📊 Loaded canonical mapping: {len(self.canonical_mapping)} scenarios")
        
        processed_count = 0
        scenario_stats = defaultdict(int)
        
        # Process all intelligence files
        for intel_file in intelligence_path.glob("*.json"):
            try:
                with open(intel_file, 'r') as f:
                    data = json.load(f)
                
                # Extract scenario fingerprint
                scenario_fp = self._extract_scenario_fingerprint(data)
                if scenario_fp:
                    self._store_scenario_fingerprint(scenario_fp, data)
                    scenario_stats[scenario_fp.canonical_name] += 1
                
                # Extract techniques
                techniques = self._extract_techniques(data)
                for technique in techniques:
                    self._store_technique(technique, scenario_fp.scenario_name if scenario_fp else None)
                
                processed_count += 1
                
                if processed_count % 50 == 0:
                    print(f"  📈 Processed {processed_count} files...")
                    
            except Exception as e:
                print(f"⚠️ Error processing {intel_file}: {e}")
        
        # Build indexes and similarity matrix
        self._build_indexes()
        self._build_similarity_matrix()
        self._build_environment_rules()
        
        print(f"\n✅ Intelligence database built successfully!")
        print(f"📊 Statistics:")
        print(f"   Files processed: {processed_count}")
        print(f"   Unique scenarios: {len(scenario_stats)}")
        
        # Convert to Counter for most_common()
        from collections import Counter
        scenario_counter = Counter(scenario_stats)
        print(f"   Top scenarios: {dict(list(scenario_counter.most_common(5)))}")
        
        # Save statistics
        self._save_database_stats(scenario_stats, processed_count)
    
    def _extract_scenario_fingerprint(self, data: Dict) -> Optional[ScenarioFingerprint]:
        """Extract scenario fingerprint from intelligence data"""
        
        scenario_data = data.get('scenario_fingerprint', {})
        if not scenario_data:
            return None
        
        scenario_name = scenario_data.get('scenario_name', 'unknown')
        canonical_name = self.canonical_mapping.get(scenario_name, scenario_name)
        
        # Parse port signature
        port_sig = scenario_data.get('port_signature', '')
        service_combo = scenario_data.get('service_combination', '')
        
        # Get confidence score
        confidence = data.get('intelligence_confidence', 0.0)
        
        # Extract key indicators
        success_indicators = []
        distinguishing_factors = scenario_data.get('distinguishing_factors', [])
        
        # Extract success patterns
        patterns = data.get('success_patterns', {})
        for factor in patterns.get('success_factors', []):
            if factor.get('recognition_patterns'):
                success_indicators.extend(factor['recognition_patterns'])
        
        return ScenarioFingerprint(
            scenario_name=scenario_name,
            canonical_name=canonical_name,
            port_signature=port_sig,
            service_combination=service_combo,
            os_family=scenario_data.get('os_family', 'unknown'),
            environment_type=scenario_data.get('environment_type', 'unknown'),
            entry_vector=scenario_data.get('entry_vector', 'unknown'),
            attack_complexity=scenario_data.get('attack_complexity', 'unknown'),
            confidence_score=confidence,
            writeup_count=1,
            success_indicators=success_indicators,
            distinguishing_factors=distinguishing_factors
        )
    
    def _extract_techniques(self, data: Dict) -> List[AttackTechnique]:
        """Extract attack techniques from intelligence data"""
        
        techniques = []
        tech_data = data.get('technique_intelligence', {})
        
        # Get success rates from different sources
        command_sequences = tech_data.get('command_sequences', [])
        sequence_success_rates = [seq.get('success_rate', 0.0) for seq in command_sequences if isinstance(seq, dict)]
        avg_sequence_success = sum(sequence_success_rates) / len(sequence_success_rates) if sequence_success_rates else 0.0
        
        # Get success rates from success patterns
        success_patterns = data.get('success_patterns', {})
        success_factors = success_patterns.get('success_factors', [])
        factor_success_rates = [factor.get('success_probability', 0.0) for factor in success_factors if isinstance(factor, dict)]
        avg_factor_success = sum(factor_success_rates) / len(factor_success_rates) if factor_success_rates else 0.0
        
        # Calculate overall success rate for this writeup
        overall_success_rate = max(avg_sequence_success, avg_factor_success)
        if overall_success_rate == 0.0:
            # Fallback based on intelligence confidence
            overall_success_rate = data.get('intelligence_confidence', 0.5)
        
        # Process individual techniques
        for i, technique in enumerate(tech_data.get('techniques', [])):
            # Extract tools and commands
            tools = technique.get('tools_used', [])
            commands = []
            
            for tool in tools:
                if tool.get('actual_command'):
                    commands.append(tool['actual_command'])
                elif tool.get('command_template'):
                    commands.append(tool['command_template'])
            
            # Extract command sequences
            for seq in command_sequences:
                for step in seq.get('steps', []):
                    if step.get('command'):
                        commands.append(step['command'])
            
            # Calculate success rate for this technique - more realistic approach
            base_success_rate = overall_success_rate
            
            # Apply more realistic base scaling (reduce from the extracted high rates)
            base_success_rate *= 0.7  # Scale down from optimistic extraction data
            
            # Adjust based on skill level (more dramatic differences)
            skill_level = technique.get('skill_level', 'intermediate').lower()
            skill_multipliers = {
                'beginner': 1.3,      # 30% bonus for beginner techniques
                'easy': 1.15,         # 15% bonus
                'intermediate': 1.0,   # baseline
                'advanced': 0.8,      # 20% penalty
                'expert': 0.65,       # 35% penalty
                'master': 0.5         # 50% penalty
            }
            technique_success_rate = base_success_rate * skill_multipliers.get(skill_level, 1.0)
            
            # Add some realistic variation based on technique name
            technique_name = technique.get('name', '').lower()
            
            # High success techniques (basic enumeration)
            if any(word in technique_name for word in ['enumeration', 'scan', 'discovery', 'directory']):
                technique_success_rate *= 1.1
            
            # Medium success techniques (exploitation)
            elif any(word in technique_name for word in ['injection', 'exploit', 'bypass', 'traversal']):
                technique_success_rate *= 0.9
            
            # Lower success techniques (advanced attacks)
            elif any(word in technique_name for word in ['privilege', 'escalation', 'persistence', 'lateral']):
                technique_success_rate *= 0.75
            
            # Very low success techniques (complex attacks)
            elif any(word in technique_name for word in ['memory', 'kernel', 'advanced', 'sophisticated']):
                technique_success_rate *= 0.6
            
            # Position-based adjustment (slight decrease for later techniques)
            position_factor = max(0.85, 1.0 - (i * 0.03))
            technique_success_rate *= position_factor
            
            # Add some realistic randomness (±10%)
            import random
            random.seed(hash(technique.get('name', '') + str(i)))  # Deterministic randomness
            variation = random.uniform(0.9, 1.1)
            technique_success_rate *= variation
            
            # Set realistic bounds (10% to 85% max)
            technique_success_rate = min(0.85, max(0.10, technique_success_rate))
            
            attack_tech = AttackTechnique(
                name=technique.get('name', 'Unknown'),
                mitre_id=technique.get('mitre_id', ''),
                category=technique.get('category', 'unknown'),
                tools=tools,
                commands=commands,
                success_rate=technique_success_rate,
                prerequisites=technique.get('prerequisites', []),
                success_indicators=technique.get('success_indicators', []),
                time_estimate=technique.get('time_investment', 'unknown'),
                difficulty=technique.get('skill_level', 'unknown')
            )
            techniques.append(attack_tech)
        
        return techniques
    
    def _store_scenario_fingerprint(self, fingerprint: ScenarioFingerprint, full_data: Dict):
        """Store scenario fingerprint in database with full data"""
        
        # Check if scenario already exists (merge if so)
        existing = self.conn.execute(
            "SELECT id, writeup_count FROM scenarios WHERE scenario_name = ?",
            (fingerprint.scenario_name,)
        ).fetchone()
        
        if existing:
            # Update writeup count
            new_count = existing['writeup_count'] + 1
            self.conn.execute(
                "UPDATE scenarios SET writeup_count = ? WHERE id = ?",
                (new_count, existing['id'])
            )
            scenario_id = existing['id']
        else:
            # Insert new scenario
            cursor = self.conn.execute("""
                INSERT INTO scenarios (
                    scenario_name, canonical_name, port_signature, service_combination,
                    os_family, environment_type, entry_vector, attack_complexity,
                    confidence_score, writeup_count, data_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                fingerprint.scenario_name,
                fingerprint.canonical_name,
                fingerprint.port_signature,
                fingerprint.service_combination,
                fingerprint.os_family,
                fingerprint.environment_type,
                fingerprint.entry_vector,
                fingerprint.attack_complexity,
                fingerprint.confidence_score,
                fingerprint.writeup_count,
                json.dumps(full_data)
            ))
            scenario_id = cursor.lastrowid
        
        # Store port mappings for fast lookup
        self._store_port_mappings(scenario_id, fingerprint.port_signature)
        
        # Store service mappings
        self._store_service_mappings(scenario_id, fingerprint.service_combination)
        
        self.conn.commit()
    
    def _store_port_mappings(self, scenario_id: int, port_signature: str):
        """Store port-to-scenario mappings for fast lookup"""
        
        if not port_signature or port_signature == 'unknown':
            return
        
        # Parse port signature (e.g., "53+88+389+445")
        ports = []
        for port_str in port_signature.replace('+', ',').split(','):
            port_str = port_str.strip()
            if port_str and port_str.isdigit():
                ports.append(int(port_str))
        
        # Store each port mapping with weight based on rarity
        for port in ports:
            # Calculate weight (rare ports get higher weight)
            weight = self._calculate_port_weight(port)
            
            # Insert or update mapping
            self.conn.execute("""
                INSERT OR REPLACE INTO port_mappings (port, protocol, scenario_id, weight)
                VALUES (?, ?, ?, ?)
            """, (port, 'tcp', scenario_id, weight))
    
    def _store_service_mappings(self, scenario_id: int, service_combination: str):
        """Store service-to-scenario mappings"""
        
        if not service_combination or service_combination == 'unknown':
            return
        
        # Parse service combination (e.g., "dns+kerberos+ldap+smb")
        services = []
        for service in service_combination.replace('+', ',').split(','):
            service = service.strip().lower()
            if service:
                services.append(service)
        
        # Store each service mapping
        for service in services:
            weight = self._calculate_service_weight(service)
            
            self.conn.execute("""
                INSERT OR REPLACE INTO service_mappings (service_name, scenario_id, weight)
                VALUES (?, ?, ?)
            """, (service, scenario_id, weight))
    
    def _calculate_port_weight(self, port: int) -> float:
        """Calculate weight for port based on rarity (higher weight = more distinctive)"""
        
        # Common ports get lower weight, rare ports get higher weight
        common_ports = {22: 0.1, 23: 0.2, 25: 0.3, 53: 0.4, 80: 0.1, 110: 0.3, 
                       135: 0.5, 139: 0.6, 143: 0.3, 443: 0.2, 445: 0.6, 993: 0.4, 995: 0.4}
        
        distinctive_ports = {88: 0.9, 389: 0.8, 636: 0.8, 3268: 0.9, 3269: 0.9,  # AD
                           1433: 0.8, 3306: 0.7, 5432: 0.7,  # Databases
                           8080: 0.5, 8443: 0.6, 8000: 0.5}  # Web alternatives
        
        if port in distinctive_ports:
            return distinctive_ports[port]
        elif port in common_ports:
            return common_ports[port]
        elif port > 1024:
            return 0.7  # High ports often interesting
        else:
            return 0.5  # Default weight
    
    def _calculate_service_weight(self, service: str) -> float:
        """Calculate weight for service based on distinctiveness"""
        
        distinctive_services = {
            'kerberos': 0.9, 'ldap': 0.8, 'smb': 0.7, 'mssql': 0.8,
            'mysql': 0.6, 'postgresql': 0.7, 'redis': 0.7, 'mongodb': 0.7,
            'elasticsearch': 0.8, 'docker': 0.8, 'kubernetes': 0.9
        }
        
        common_services = {
            'http': 0.2, 'https': 0.3, 'ssh': 0.3, 'ftp': 0.4, 'telnet': 0.5,
            'smtp': 0.4, 'dns': 0.4, 'snmp': 0.6
        }
        
        service_lower = service.lower()
        
        if service_lower in distinctive_services:
            return distinctive_services[service_lower]
        elif service_lower in common_services:
            return common_services[service_lower]
        else:
            return 0.5
    
    def _store_technique(self, technique: AttackTechnique, scenario_name: str = None):
        """Store attack technique in database"""
        
        # Get scenario_id if provided
        scenario_id = None
        if scenario_name:
            result = self.conn.execute(
                "SELECT id FROM scenarios WHERE scenario_name = ?",
                (scenario_name,)
            ).fetchone()
            if result:
                scenario_id = result['id']
        
        # Store technique
        self.conn.execute("""
            INSERT INTO techniques (
                name, mitre_id, category, success_rate, difficulty,
                time_estimate, scenario_id, data_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            technique.name,
            technique.mitre_id,
            technique.category,
            technique.success_rate,
            technique.difficulty,
            technique.time_estimate,
            scenario_id,
            json.dumps(asdict(technique))
        ))
    
    def _build_indexes(self):
        """Build in-memory indexes for lightning-fast queries"""
        
        print("🔄 Building performance indexes...")
        
        # Port index: port -> [scenario_ids with weights]
        self.indexes['ports'] = defaultdict(list)
        port_data = self.conn.execute("""
            SELECT port, scenario_id, weight FROM port_mappings
        """).fetchall()
        
        for row in port_data:
            self.indexes['ports'][row['port']].append({
                'scenario_id': row['scenario_id'],
                'weight': row['weight']
            })
        
        # Service index: service -> [scenario_ids with weights]
        self.indexes['services'] = defaultdict(list)
        service_data = self.conn.execute("""
            SELECT service_name, scenario_id, weight FROM service_mappings
        """).fetchall()
        
        for row in service_data:
            self.indexes['services'][row['service_name']].append({
                'scenario_id': row['scenario_id'],
                'weight': row['weight']
            })
        
        # Environment index: (os, env_type) -> [scenario_ids]
        self.indexes['environments'] = defaultdict(list)
        env_data = self.conn.execute("""
            SELECT id, os_family, environment_type FROM scenarios
        """).fetchall()
        
        for row in env_data:
            key = (row['os_family'], row['environment_type'])
            self.indexes['environments'][key].append(row['id'])
        
        # Canonical name index for quick canonical lookups
        self.indexes['canonical'] = {}
        canonical_data = self.conn.execute("""
            SELECT canonical_name, COUNT(*) as count FROM scenarios 
            GROUP BY canonical_name
        """).fetchall()
        
        for row in canonical_data:
            self.indexes['canonical'][row['canonical_name']] = row['count']
        
        print(f"✅ Built indexes: {len(self.indexes['ports'])} ports, {len(self.indexes['services'])} services")
    
    def _build_similarity_matrix(self):
        """Build scenario similarity matrix for recommendations"""
        
        print("🔄 Building scenario similarity matrix...")
        
        scenarios = self.conn.execute("""
            SELECT id, scenario_name, port_signature, service_combination, 
                   os_family, environment_type, entry_vector
            FROM scenarios
        """).fetchall()
        
        self.similarity_matrix = {}
        
        for i, scenario1 in enumerate(scenarios):
            similarities = []
            
            for j, scenario2 in enumerate(scenarios):
                if i != j:
                    similarity = self._calculate_scenario_similarity(scenario1, scenario2)
                    if similarity > 0.3:  # Only store meaningful similarities
                        similarities.append({
                            'scenario_id': scenario2['id'],
                            'scenario_name': scenario2['scenario_name'],
                            'similarity': similarity
                        })
            
            # Sort by similarity and keep top 5
            similarities.sort(key=lambda x: x['similarity'], reverse=True)
            self.similarity_matrix[scenario1['id']] = similarities[:5]
        
        print(f"✅ Built similarity matrix for {len(scenarios)} scenarios")
    
    def _calculate_scenario_similarity(self, scenario1: sqlite3.Row, scenario2: sqlite3.Row) -> float:
        """Calculate similarity score between two scenarios"""
        
        similarity = 0.0
        
        # Port signature similarity (30% weight)
        if scenario1['port_signature'] and scenario2['port_signature']:
            ports1 = set(scenario1['port_signature'].replace('+', ',').split(','))
            ports2 = set(scenario2['port_signature'].replace('+', ',').split(','))
            if ports1 and ports2:
                overlap = len(ports1.intersection(ports2))
                union = len(ports1.union(ports2))
                if union > 0:
                    similarity += 0.3 * (overlap / union)
        
        # Service similarity (25% weight)
        if scenario1['service_combination'] and scenario2['service_combination']:
            services1 = set(scenario1['service_combination'].replace('+', ',').split(','))
            services2 = set(scenario2['service_combination'].replace('+', ',').split(','))
            if services1 and services2:
                overlap = len(services1.intersection(services2))
                union = len(services1.union(services2))
                if union > 0:
                    similarity += 0.25 * (overlap / union)
        
        # OS family similarity (20% weight)
        if scenario1['os_family'] == scenario2['os_family'] and scenario1['os_family'] != 'unknown':
            similarity += 0.2
        
        # Environment type similarity (15% weight)
        if scenario1['environment_type'] == scenario2['environment_type'] and scenario1['environment_type'] != 'unknown':
            similarity += 0.15
        
        # Entry vector similarity (10% weight)
        if scenario1['entry_vector'] == scenario2['entry_vector'] and scenario1['entry_vector'] != 'unknown':
            similarity += 0.1
        
        return similarity
    
    def _build_environment_rules(self):
        """Build environment detection rules"""
        
        print("🔄 Building environment detection rules...")
        
        # Analyze patterns to create detection rules
        env_patterns = defaultdict(lambda: {'ports': Counter(), 'services': Counter(), 'count': 0})
        
        scenarios = self.conn.execute("""
            SELECT environment_type, port_signature, service_combination FROM scenarios
            WHERE environment_type != 'unknown'
        """).fetchall()
        
        for scenario in scenarios:
            env_type = scenario['environment_type']
            env_patterns[env_type]['count'] += 1
            
            # Analyze port patterns
            if scenario['port_signature']:
                for port in scenario['port_signature'].replace('+', ',').split(','):
                    if port.strip().isdigit():
                        env_patterns[env_type]['ports'][int(port.strip())] += 1
            
            # Analyze service patterns
            if scenario['service_combination']:
                for service in scenario['service_combination'].replace('+', ',').split(','):
                    if service.strip():
                        env_patterns[env_type]['services'][service.strip().lower()] += 1
        
        # Create detection rules
        for env_type, patterns in env_patterns.items():
            if patterns['count'] >= 3:  # Only create rules for environments with multiple examples
                
                # Top ports for this environment
                top_ports = [str(port) for port, count in patterns['ports'].most_common(5) 
                           if count >= patterns['count'] * 0.3]
                
                # Top services for this environment
                top_services = [service for service, count in patterns['services'].most_common(5)
                              if count >= patterns['count'] * 0.3]
                
                if top_ports or top_services:
                    rule = {
                        'ports': top_ports,
                        'services': top_services,
                        'min_matches': max(1, len(top_ports + top_services) // 2)
                    }
                    
                    confidence = min(0.9, patterns['count'] / 10.0)  # More examples = higher confidence
                    
                    self.conn.execute("""
                        INSERT OR REPLACE INTO environment_rules 
                        (environment_type, detection_rule, confidence_threshold, scenario_count)
                        VALUES (?, ?, ?, ?)
                    """, (env_type, json.dumps(rule), confidence, patterns['count']))
        
        self.conn.commit()
        print(f"✅ Built environment detection rules")
    
    def _save_database_stats(self, scenario_stats: Dict, processed_count: int):
        """Save database statistics"""
        
        from collections import Counter
        scenario_counter = Counter(scenario_stats)
        
        stats = {
            'database_info': {
                'created_at': datetime.now().isoformat(),
                'total_files_processed': processed_count,
                'unique_scenarios': len(scenario_stats),
                'canonical_scenarios': len(self.indexes.get('canonical', {})),
                'total_techniques': self.conn.execute("SELECT COUNT(*) FROM techniques").fetchone()[0],
                'port_mappings': len(self.indexes.get('ports', {})),
                'service_mappings': len(self.indexes.get('services', {}))
            },
            'scenario_distribution': dict(scenario_counter.most_common(20)),
            'canonical_distribution': self.indexes.get('canonical', {}),
            'port_coverage': {
                str(port): len(mappings) for port, mappings in 
                list(self.indexes.get('ports', {}).items())[:20]
            },
            'service_coverage': {
                service: len(mappings) for service, mappings in 
                list(self.indexes.get('services', {}).items())[:20]
            }
        }
        
        stats_file = self.db_path / "metadata" / "database_stats.json"
        stats_file.parent.mkdir(exist_ok=True)
        
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
        
        print(f"💾 Database statistics saved to {stats_file}")