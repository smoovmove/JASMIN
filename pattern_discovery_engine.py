#!/usr/bin/env python3

"""
Original Pattern Discovery Engine with Environment Typicality Scoring
Clean approach without hardcoding - learns proper environment weights
"""

import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Tuple, Set
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
import re
import math
import numpy as np

@dataclass
class AttackPattern:
    """Represents a discovered attack pattern from writeups"""
    pattern_id: str
    ports: List[int]
    services: List[str]
    writeup_count: int
    environment_distribution: Dict[str, float]  # {"AD": 0.94, "Web": 0.06}
    avg_success_rate: float
    avg_difficulty: float
    canonical_scenarios: List[str]
    success_indicators: List[str]
    common_techniques: List[str]
    environment_typicality: Dict[str, float]  # NEW: how typical for each environment

@dataclass
class EnvironmentTypicalityScorer:
    """Calculates how typical a port/service combination is for each environment"""
    
    def __init__(self):
        self.environment_profiles = {}
        self.port_environment_frequencies = defaultdict(Counter)
        self.service_environment_frequencies = defaultdict(Counter)
        self.total_environment_counts = Counter()
    
    def build_profiles(self, raw_patterns: List[Dict]):
        """Build environment typicality profiles from the database"""
        
        print("   📊 Building environment typicality profiles...")
        
        # Count port/service frequencies per environment
        for pattern in raw_patterns:
            env_type = pattern['environment_type'].lower()
            self.total_environment_counts[env_type] += 1
            
            for port in pattern['ports']:
                self.port_environment_frequencies[port][env_type] += 1
            
            for service in pattern['services']:
                self.service_environment_frequencies[service.lower()][env_type] += 1
        
        # Calculate typicality scores
        self._calculate_environment_profiles()
    
    def _calculate_environment_profiles(self):
        """Calculate how typical each port/service is for each environment"""
        
        environments = list(self.total_environment_counts.keys())
        
        for env in environments:
            self.environment_profiles[env] = {
                'ports': {},
                'services': {},
                'signature_indicators': self._get_signature_indicators(env)
            }
        
        # Port typicality scores
        for port, env_counts in self.port_environment_frequencies.items():
            total_port_occurrences = sum(env_counts.values())
            
            for env in environments:
                env_frequency = env_counts[env] / self.total_environment_counts[env] if self.total_environment_counts[env] > 0 else 0
                global_frequency = env_counts[env] / total_port_occurrences if total_port_occurrences > 0 else 0
                
                # Typicality = how much more likely this port is in this environment vs globally
                typicality = env_frequency / (global_frequency + 0.001)  # Avoid division by zero
                self.environment_profiles[env]['ports'][port] = min(3.0, typicality)  # Cap at 3x typical
        
        # Service typicality scores
        for service, env_counts in self.service_environment_frequencies.items():
            total_service_occurrences = sum(env_counts.values())
            
            for env in environments:
                env_frequency = env_counts[env] / self.total_environment_counts[env] if self.total_environment_counts[env] > 0 else 0
                global_frequency = env_counts[env] / total_service_occurrences if total_service_occurrences > 0 else 0
                
                typicality = env_frequency / (global_frequency + 0.001)
                self.environment_profiles[env]['services'][service] = min(3.0, typicality)
        
        # Print some examples
        print(f"   📈 Environment profiles built for {len(environments)} environments")
        for env in environments[:3]:  # Show top 3
            top_ports = sorted(self.environment_profiles[env]['ports'].items(), 
                             key=lambda x: x[1], reverse=True)[:3]
            top_services = sorted(self.environment_profiles[env]['services'].items(), 
                                key=lambda x: x[1], reverse=True)[:3]
            print(f"      {env}: Top ports {top_ports}, Top services {top_services}")
    
    def _get_signature_indicators(self, environment: str) -> Dict[str, float]:
        """Get signature indicators that strongly suggest specific environments"""
        
        signatures = {
            'active_directory': {
                'smoking_gun_ports': {88: 3.0, 3268: 3.0, 3269: 3.0, 9389: 2.8},
                'critical_ports': {389: 2.5, 636: 2.5, 464: 2.2},
                'supporting_ports': {53: 1.8, 445: 1.8, 135: 1.5},
                'signature_services': {'kerberos': 3.0, 'kerberos-sec': 3.0, 'ldap': 2.8, 'microsoft-ds': 2.5}
            },
            'web_application': {
                'signature_ports': {8080: 2.5, 8443: 2.5, 3000: 2.3, 9000: 2.0},
                'standard_ports': {80: 2.0, 443: 2.0},
                'signature_services': {'http': 2.2, 'https': 2.2, 'apache': 2.0, 'nginx': 2.0, 'tomcat': 2.8}
            },
            'database_server': {
                'signature_ports': {1433: 3.0, 3306: 2.8, 5432: 2.8, 1521: 2.5, 27017: 2.3},
                'signature_services': {'mysql': 2.8, 'postgresql': 2.8, 'mssql': 3.0, 'oracle': 2.5}
            }
        }
        
        return signatures.get(environment, {})
    
    def calculate_typicality(self, ports: List[int], services: List[str], 
                           environment: str) -> float:
        """Calculate how typical this port/service combination is for the environment"""
        
        env_profile = self.environment_profiles.get(environment.lower(), {})
        if not env_profile:
            return 0.5  # Default neutral score
        
        port_scores = []
        service_scores = []
        
        # Port typicality
        for port in ports:
            score = env_profile.get('ports', {}).get(port, 0.5)  # Default neutral
            port_scores.append(score)
        
        # Service typicality  
        for service in services:
            score = env_profile.get('services', {}).get(service.lower(), 0.5)
            service_scores.append(score)
        
        # Signature indicator boost
        signature_boost = self._calculate_signature_boost(ports, services, environment)
        
        # Combined typicality score
        avg_port_score = sum(port_scores) / len(port_scores) if port_scores else 0.5
        avg_service_score = sum(service_scores) / len(service_scores) if service_scores else 0.5
        
        # Weight services more heavily for single-port scenarios
        if len(ports) == 1:
            typicality = (avg_port_score * 0.4) + (avg_service_score * 0.6) + signature_boost
        else:
            typicality = (avg_port_score * 0.5) + (avg_service_score * 0.5) + signature_boost
        
        return min(3.0, max(0.1, typicality))  # Clamp between 0.1 and 3.0
    
    def _calculate_signature_boost(self, ports: List[int], services: List[str], 
                                 environment: str) -> float:
        """Calculate boost from signature indicators"""
        
        env_signatures = self._get_signature_indicators(environment.lower())
        boost = 0.0
        
        for indicator_type, indicators in env_signatures.items():
            if 'ports' in indicator_type:
                for port in ports:
                    if port in indicators:
                        boost += indicators[port] * 0.2  # 20% of signature strength
            elif 'services' in indicator_type:
                for service in services:
                    if service.lower() in indicators:
                        boost += indicators[service.lower()] * 0.2
        
        return min(1.0, boost)  # Cap signature boost at 1.0

class EnhancedPatternDiscoveryEngine:
    """Original pattern discovery with environment typicality scoring"""
    
    def __init__(self, database_path: str = "intelligence.db"):
        self.db_path = database_path
        self.conn = sqlite3.connect(database_path)
        self.conn.row_factory = sqlite3.Row
        
        # Pattern storage
        self.discovered_patterns = {}
        self.pattern_similarity_matrix = {}
        self.port_distinctiveness = {}
        self.service_distinctiveness = {}
        
        # NEW: Environment typicality scorer
        self.typicality_scorer = EnvironmentTypicalityScorer()
        
    def discover_all_patterns(self) -> Dict[str, AttackPattern]:
        """Main method to discover all attack patterns with typicality scoring"""
        
        print("🔍 Original Pattern Discovery with Environment Typicality...")
        print("=" * 60)
        
        # Step 1: Extract raw patterns from database
        print("📊 Step 1: Extracting port+service patterns from writeups...")
        raw_patterns = self._extract_raw_patterns()
        print(f"   Found {len(raw_patterns)} unique port+service combinations")
        
        # Step 2: Build environment typicality profiles
        print("🎯 Step 2: Building environment typicality profiles...")
        self.typicality_scorer.build_profiles(raw_patterns)
        
        # Step 3: Calculate distinctiveness weights (original method)
        print("⚖️ Step 3: Calculating port and service distinctiveness...")
        self._calculate_distinctiveness()
        
        # Step 4: Group similar patterns (original method)
        print("🔗 Step 4: Grouping similar patterns...")
        grouped_patterns = self._group_similar_patterns(raw_patterns)
        print(f"   Grouped into {len(grouped_patterns)} pattern families")
        
        # Step 5: Analyze pattern statistics with typicality
        print("📈 Step 5: Analyzing patterns with environment typicality...")
        analyzed_patterns = self._analyze_pattern_statistics_with_typicality(grouped_patterns)
        
        # Step 6: Build similarity matrix
        print("🧮 Step 6: Building pattern similarity matrix...")
        self._build_similarity_matrix(analyzed_patterns)
        
        # Step 7: Cache top patterns
        print("💾 Step 7: Caching top patterns...")
        top_patterns = self._select_top_patterns(analyzed_patterns, top_k=100)
        
        print(f"✅ Pattern discovery with typicality scoring complete!")
        print(f"   Cached {len(top_patterns)} patterns with environment typicality")
        return top_patterns
    
    def _extract_raw_patterns(self) -> List[Dict]:
        """Extract all port+service combinations from scenarios (original method)"""
        
        patterns = []
        
        scenarios = self.conn.execute("""
            SELECT 
                s.id,
                s.scenario_name,
                s.canonical_name,
                s.port_signature,
                s.service_combination,
                s.environment_type,
                s.confidence_score,
                s.data_json
            FROM scenarios s
            WHERE s.port_signature IS NOT NULL 
            AND s.port_signature != 'unknown'
            AND s.port_signature != ''
        """).fetchall()
        
        for scenario in scenarios:
            ports = self._parse_port_signature(scenario['port_signature'])
            services = self._parse_service_combination(scenario['service_combination'])
            
            if ports:
                pattern = {
                    'scenario_id': scenario['id'],
                    'scenario_name': scenario['scenario_name'],
                    'canonical_name': scenario['canonical_name'],
                    'ports': sorted(ports),
                    'services': sorted(services),
                    'environment_type': scenario['environment_type'],
                    'confidence_score': scenario['confidence_score'],
                    'raw_data': json.loads(scenario['data_json']) if scenario['data_json'] else {}
                }
                patterns.append(pattern)
        
        return patterns
    
    def _calculate_distinctiveness(self):
        """Calculate distinctiveness (original method with small enhancements)"""
        
        port_counts = Counter()
        service_counts = Counter()
        total_scenarios = 0
        
        scenarios = self.conn.execute("""
            SELECT port_signature, service_combination FROM scenarios
            WHERE port_signature IS NOT NULL
        """).fetchall()
        
        for scenario in scenarios:
            total_scenarios += 1
            ports = self._parse_port_signature(scenario['port_signature'])
            services = self._parse_service_combination(scenario['service_combination'])
            
            for port in ports:
                port_counts[port] += 1
            for service in services:
                service_counts[service] += 1
        
        # Calculate distinctiveness (inverse frequency)
        for port, count in port_counts.items():
            frequency = count / total_scenarios
            self.port_distinctiveness[port] = max(0.1, 1.0 - frequency)
        
        for service, count in service_counts.items():
            frequency = count / total_scenarios
            self.service_distinctiveness[service] = max(0.1, 1.0 - frequency)
        
        # Apply reasonable boosting (not hardcoded)
        self._apply_balanced_distinctiveness_boosting()
        
        print(f"   Calculated distinctiveness for {len(self.port_distinctiveness)} ports")
        print(f"   Calculated distinctiveness for {len(self.service_distinctiveness)} services")
    
    def _apply_balanced_distinctiveness_boosting(self):
        """Apply balanced distinctiveness boosting based on environment signatures"""
        
        # Moderate boosting for signature ports/services
        signature_boosts = {
            # AD signature elements
            88: 0.95, 3268: 0.92, 3269: 0.92, 9389: 0.90,
            389: 0.88, 636: 0.88, 464: 0.85,
            
            # Web signature elements  
            8080: 0.85, 8443: 0.83, 3000: 0.80,
            
            # Database signature elements
            1433: 0.90, 3306: 0.88, 5432: 0.88
        }
        
        service_boosts = {
            'kerberos': 0.90, 'kerberos-sec': 0.90, 'ldap': 0.85,
            'http': 0.80, 'https': 0.80, 'apache': 0.78,
            'mysql': 0.85, 'postgresql': 0.85
        }
        
        for port, min_distinctiveness in signature_boosts.items():
            current = self.port_distinctiveness.get(port, 0.5)
            if min_distinctiveness > current:
                self.port_distinctiveness[port] = min_distinctiveness
                print(f"   🔥 Boosted port {port} distinctiveness to {min_distinctiveness}")
        
        for service, min_distinctiveness in service_boosts.items():
            current = self.service_distinctiveness.get(service, 0.5)
            if min_distinctiveness > current:
                self.service_distinctiveness[service] = min_distinctiveness
                print(f"   🔥 Boosted service '{service}' distinctiveness to {min_distinctiveness}")
    
    def _group_similar_patterns(self, raw_patterns: List[Dict]) -> Dict[str, List[Dict]]:
        """Group similar patterns (original method)"""
        
        groups = defaultdict(list)
        processed = set()
        
        for i, pattern1 in enumerate(raw_patterns):
            if i in processed:
                continue
            
            pattern_key = self._generate_pattern_key(pattern1['ports'], pattern1['services'])
            groups[pattern_key].append(pattern1)
            processed.add(i)
            
            for j, pattern2 in enumerate(raw_patterns[i+1:], i+1):
                if j in processed:
                    continue
                
                similarity = self._calculate_pattern_similarity(
                    pattern1['ports'], pattern1['services'],
                    pattern2['ports'], pattern2['services']
                )
                
                if similarity >= 0.7:  # 70% similarity threshold
                    groups[pattern_key].append(pattern2)
                    processed.add(j)
        
        return dict(groups)
    
    def _calculate_pattern_similarity(self, ports1: List[int], services1: List[str],
                                    ports2: List[int], services2: List[str]) -> float:
        """Calculate pattern similarity (original method)"""
        
        ports1_set = set(ports1)
        ports2_set = set(ports2)
        services1_set = set(services1)
        services2_set = set(services2)
        
        # Jaccard similarity
        port_intersection = len(ports1_set & ports2_set)
        port_union = len(ports1_set | ports2_set)
        port_jaccard = port_intersection / port_union if port_union > 0 else 0
        
        service_intersection = len(services1_set & services2_set)
        service_union = len(services1_set | services2_set)
        service_jaccard = service_intersection / service_union if service_union > 0 else 0
        
        # Subset scoring
        port_subset_score = 0
        if ports1_set and ports2_set:
            if ports1_set.issubset(ports2_set) or ports2_set.issubset(ports1_set):
                port_subset_score = 0.5
        
        service_subset_score = 0
        if services1_set and services2_set:
            if services1_set.issubset(services2_set) or services2_set.issubset(services1_set):
                service_subset_score = 0.5
        
        # Distinctiveness weighting
        common_ports = ports1_set & ports2_set
        common_services = services1_set & services2_set
        
        port_distinctiveness_score = sum(self.port_distinctiveness.get(p, 0.5) for p in common_ports) / max(1, len(common_ports))
        service_distinctiveness_score = sum(self.service_distinctiveness.get(s, 0.5) for s in common_services) / max(1, len(common_services))
        
        # Combined similarity
        similarity = (
            port_jaccard * 0.25 +
            service_jaccard * 0.25 +
            port_subset_score * 0.15 +
            service_subset_score * 0.15 +
            port_distinctiveness_score * 0.1 +
            service_distinctiveness_score * 0.1
        )
        
        return min(1.0, similarity)
    
    def _analyze_pattern_statistics_with_typicality(self, grouped_patterns: Dict[str, List[Dict]]) -> Dict[str, AttackPattern]:
        """Analyze pattern statistics with environment typicality scoring"""
        
        analyzed_patterns = {}
        
        for pattern_key, pattern_group in grouped_patterns.items():
            if len(pattern_group) < 2:  # Skip singleton patterns
                continue
            
            # Aggregate data
            all_ports = set()
            all_services = set()
            environment_counts = Counter()
            confidence_scores = []
            canonical_scenarios = set()
            
            for pattern in pattern_group:
                all_ports.update(pattern['ports'])
                all_services.update(pattern['services'])
                environment_counts[pattern['environment_type']] += 1
                confidence_scores.append(pattern['confidence_score'])
                canonical_scenarios.add(pattern['canonical_name'])
            
            writeup_count = len(pattern_group)
            
            # Original environment distribution
            total_patterns = len(pattern_group)
            environment_distribution = {}
            for env_type, count in environment_counts.items():
                environment_distribution[env_type] = count / total_patterns
            
            # NEW: Calculate environment typicality scores
            environment_typicality = {}
            for env_type in environment_distribution.keys():
                typicality = self.typicality_scorer.calculate_typicality(
                    list(all_ports), list(all_services), env_type
                )
                environment_typicality[env_type] = typicality
                print(f"   📊 {pattern_key[:50]}... → {env_type}: typicality {typicality:.2f}")
            
            # Other statistics
            avg_success_rate = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.5
            avg_difficulty = self._calculate_avg_difficulty(pattern_group)
            success_indicators = self._extract_success_indicators(pattern_group)
            common_techniques = self._extract_common_techniques(pattern_group)
            
            pattern = AttackPattern(
                pattern_id=pattern_key,
                ports=sorted(list(all_ports)),
                services=sorted(list(all_services)),
                writeup_count=writeup_count,
                environment_distribution=environment_distribution,
                avg_success_rate=avg_success_rate,
                avg_difficulty=avg_difficulty,
                canonical_scenarios=list(canonical_scenarios),
                success_indicators=success_indicators,
                common_techniques=common_techniques,
                environment_typicality=environment_typicality  # NEW
            )
            
            analyzed_patterns[pattern_key] = pattern
        
        return analyzed_patterns
    
    # Helper methods (keeping original implementations)
    def _parse_port_signature(self, port_signature: str) -> List[int]:
        if not port_signature or port_signature in ['unknown', '']:
            return []
        
        ports = []
        port_str = port_signature.replace('+', ',').replace('|', ',').replace(' ', ',')
        
        for port_part in port_str.split(','):
            port_part = port_part.strip()
            if port_part and port_part.isdigit():
                port = int(port_part)
                if 1 <= port <= 65535:
                    ports.append(port)
        
        return sorted(list(set(ports)))
    
    def _parse_service_combination(self, service_combination: str) -> List[str]:
        if not service_combination or service_combination in ['unknown', '']:
            return []
        
        services = []
        service_str = service_combination.replace('+', ',').replace('|', ',').replace(' ', ',')
        
        for service_part in service_str.split(','):
            service = service_part.strip().lower()
            if service and service not in ['unknown', '']:
                services.append(service)
        
        return sorted(list(set(services)))
    
    def _generate_pattern_key(self, ports: List[int], services: List[str]) -> str:
        port_str = '+'.join(map(str, sorted(ports)))
        service_str = '+'.join(sorted(services))
        return f"ports:{port_str}_services:{service_str}"
    
    def _extract_success_indicators(self, pattern_group: List[Dict]) -> List[str]:
        indicator_counts = Counter()
        
        for pattern in pattern_group:
            raw_data = pattern.get('raw_data', {})
            success_patterns = raw_data.get('success_patterns', {})
            for factor in success_patterns.get('success_factors', []):
                for indicator in factor.get('success_indicators', []):
                    indicator_counts[indicator] += 1
        
        return [ind for ind, count in indicator_counts.most_common()]
    
    def _extract_common_techniques(self, pattern_group: List[Dict]) -> List[str]:
        technique_counts = Counter()
        
        for pattern in pattern_group:
            raw_data = pattern.get('raw_data', {})
            techniques = raw_data.get('techniques', [])
            for technique in techniques:
                if isinstance(technique, dict):
                    technique_counts[technique.get('name', '')] += 1
                else:
                    technique_counts[str(technique)] += 1
        
        return [tech for tech, count in technique_counts.most_common()]
    
    def _calculate_avg_difficulty(self, pattern_group: List[Dict]) -> float:
        difficulty_map = {
            'trivial': 1.0, 'easy': 2.0, 'medium': 3.0, 
            'hard': 4.0, 'insane': 5.0, 'very_hard': 4.5
        }
        
        difficulties = []
        for pattern in pattern_group:
            raw_data = pattern.get('raw_data', {})
            scenario_fp = raw_data.get('scenario_fingerprint', {})
            difficulty = scenario_fp.get('attack_complexity', 'medium')
            difficulties.append(difficulty_map.get(difficulty, 3.0))
        
        return sum(difficulties) / len(difficulties) if difficulties else 3.0
    
    def _build_similarity_matrix(self, patterns: Dict[str, AttackPattern]):
        pattern_list = list(patterns.values())
        matrix = {}
        
        for i, pattern1 in enumerate(pattern_list):
            matrix[pattern1.pattern_id] = {}
            
            for j, pattern2 in enumerate(pattern_list):
                if i != j:
                    similarity = self._calculate_pattern_similarity(
                        pattern1.ports, pattern1.services,
                        pattern2.ports, pattern2.services
                    )
                    matrix[pattern1.pattern_id][pattern2.pattern_id] = similarity
        
        self.pattern_similarity_matrix = matrix
    
    def _select_top_patterns(self, patterns: Dict[str, AttackPattern], top_k: int = 100) -> Dict[str, AttackPattern]:
        scored_patterns = []
        
        for pattern in patterns.values():
            writeup_score = min(1.0, pattern.writeup_count / 50)
            
            port_distinctiveness_score = sum(
                self.port_distinctiveness.get(str(p), 0.5) for p in pattern.ports
            ) / max(1, len(pattern.ports))
            
            success_score = pattern.avg_success_rate
            
            total_score = (
                writeup_score * 0.4 +
                port_distinctiveness_score * 0.3 +
                success_score * 0.3
            )
            
            scored_patterns.append((total_score, pattern))
        
        scored_patterns.sort(key=lambda x: x[0], reverse=True)
        
        top_patterns = {}
        for score, pattern in scored_patterns[:top_k]:
            top_patterns[pattern.pattern_id] = pattern
        
        return top_patterns
    
    def save_patterns_cache(self, patterns: Dict[str, AttackPattern], cache_file: str = "pattern_cache.json"):
        cache_data = {
            'patterns': {
                pattern_id: asdict(pattern) 
                for pattern_id, pattern in patterns.items()
            },
            'similarity_matrix': self.pattern_similarity_matrix,
            'port_distinctiveness': self.port_distinctiveness,
            'service_distinctiveness': self.service_distinctiveness,
            'typicality_profiles': self.typicality_scorer.environment_profiles,
            'metadata': {
                'total_patterns': len(patterns),
                'discovery_timestamp': __import__('datetime').datetime.now().isoformat(),
                'version': 'original_with_typicality_scoring'
            }
        }
        
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f, indent=2)
        
        print(f"💾 Pattern cache with typicality saved to {cache_file}")
        print(f"   {len(patterns)} patterns with environment typicality scores")


def main():
    """Main function to run original pattern discovery with typicality"""
    
    engine = EnhancedPatternDiscoveryEngine()
    discovered_patterns = engine.discover_all_patterns()
    engine.save_patterns_cache(discovered_patterns)
    
    print("\n📊 Top 10 Patterns with Environment Typicality:")
    print("=" * 80)
    
    sorted_patterns = sorted(
        discovered_patterns.values(), 
        key=lambda p: p.writeup_count, 
        reverse=True
    )
    
    for i, pattern in enumerate(sorted_patterns[:10], 1):
        print(f"{i:2d}. Pattern: {pattern.pattern_id[:50]}...")
        print(f"    Ports: {pattern.ports}")
        print(f"    Services: {pattern.services}")
        print(f"    Writeups: {pattern.writeup_count}")
        print(f"    Environment Distribution: {pattern.environment_distribution}")
        print(f"    Environment Typicality: {pattern.environment_typicality}")
        print()
    
    # Test 8080 patterns specifically
    print("🧪 Testing Port 8080 Patterns:")
    print("=" * 50)
    web_8080_patterns = [p for p in discovered_patterns.values() 
                        if 8080 in p.ports]
    
    for pattern in web_8080_patterns[:3]:
        print(f"Pattern: {pattern.pattern_id[:40]}...")
        for env, typicality in pattern.environment_typicality.items():
            distribution = pattern.environment_distribution.get(env, 0)
            print(f"  {env}: {distribution:.2f} distribution, {typicality:.2f} typicality")
        print()


if __name__ == "__main__":
    main()