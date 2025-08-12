import json
from typing import Dict, List
from collections import defaultdict
from intelligence_core import IntelligenceDatabase

class IntelligenceAnalytics:
    """Statistical analysis and success rate calculations"""
    
    def __init__(self, database: IntelligenceDatabase):
        self.db = database
    
    def get_technique_success_rates(self, canonical_scenario: str = None, 
                                  environment_type: str = None) -> List[Dict]:
        """Get technique success rates with statistical confidence"""
        
        # Build query based on filters
        base_query = """
            SELECT 
                t.name,
                t.mitre_id,
                t.category,
                AVG(t.success_rate) as avg_success_rate,
                COUNT(*) as usage_count,
                MIN(t.success_rate) as min_rate,
                MAX(t.success_rate) as max_rate,
                s.canonical_name,
                GROUP_CONCAT(DISTINCT s.attack_complexity) as complexity_levels
            FROM techniques t 
            JOIN scenarios s ON t.scenario_id = s.id 
        """
        
        filters = []
        params = []
        
        if canonical_scenario:
            filters.append("s.canonical_name = ?")
            params.append(canonical_scenario)
        
        if environment_type:
            filters.append("s.environment_type = ?")
            params.append(environment_type)
        
        if filters:
            base_query += " WHERE " + " AND ".join(filters)
        
        base_query += """
            GROUP BY t.name, t.mitre_id, t.category
            HAVING COUNT(*) >= 2  -- Only techniques with multiple examples
            ORDER BY avg_success_rate DESC, usage_count DESC
        """
        
        results = self.db.conn.execute(base_query, params).fetchall()
        
        # Calculate statistical confidence
        total_scenarios = self._get_total_scenarios(canonical_scenario, environment_type)
        
        technique_stats = []
        for result in results:
            # Calculate confidence based on sample size and variance
            confidence = self._calculate_statistical_confidence(
                result['usage_count'], 
                total_scenarios,
                result['min_rate'],
                result['max_rate']
            )
            
            technique_stats.append({
                'technique': result['name'],
                'mitre_id': result['mitre_id'],
                'category': result['category'],
                'success_rate': result['avg_success_rate'],
                'usage_count': result['usage_count'],
                'total_scenarios': total_scenarios,
                'confidence': confidence,
                'rate_range': (result['min_rate'], result['max_rate']),
                'complexity_levels': result['complexity_levels'].split(',') if result['complexity_levels'] else [],
                'sample_quality': 'high' if result['usage_count'] >= 5 else 'medium' if result['usage_count'] >= 3 else 'low'
            })
        
        return technique_stats
    
    def get_canonical_scenario_stats(self) -> List[Dict]:
        """Get statistics for all canonical scenarios"""
        
        stats = self.db.conn.execute("""
            SELECT 
                canonical_name,
                COUNT(*) as scenario_count,
                AVG(confidence_score) as avg_confidence,
                COUNT(DISTINCT environment_type) as env_diversity,
                COUNT(DISTINCT os_family) as os_diversity,
                GROUP_CONCAT(DISTINCT attack_complexity) as complexity_range
            FROM scenarios 
            GROUP BY canonical_name
            ORDER BY scenario_count DESC
        """).fetchall()
        
        canonical_stats = []
        for stat in stats:
            canonical_stats.append({
                'canonical_name': stat['canonical_name'],
                'scenario_count': stat['scenario_count'],
                'avg_confidence': stat['avg_confidence'],
                'environment_diversity': stat['env_diversity'],
                'os_diversity': stat['os_diversity'],
                'complexity_range': stat['complexity_range'].split(',') if stat['complexity_range'] else [],
                'data_quality': self._assess_data_quality(stat['scenario_count'], stat['avg_confidence'])
            })
        
        return canonical_stats
    
    def generate_success_rate_report(self, canonical_scenario: str = None, 
                                   top_n: int = 10) -> str:
        """Generate visual success rate report"""
        
        if canonical_scenario:
            techniques = self.get_technique_success_rates(canonical_scenario)
            title = f"{canonical_scenario.replace('_', ' ').title()} Success Rates"
        else:
            # Get top techniques across all scenarios
            techniques = self.get_technique_success_rates()
            title = "Top Technique Success Rates (All Scenarios)"
        
        if not techniques:
            return f"No technique data found for {canonical_scenario or 'any scenario'}"
        
        # Limit to top N
        techniques = techniques[:top_n]
        
        # Generate visual report
        report_lines = []
        report_lines.append(f"📊 {title.upper()} (from 0xdf database)")
        report_lines.append("┌" + "─" * 65 + "┐")
        
        max_name_length = max(len(t['technique']) for t in techniques)
        max_name_length = min(max_name_length, 35)  # Cap at 35 chars
        
        for technique in techniques:
            name = technique['technique']
            if len(name) > max_name_length:
                name = name[:max_name_length-3] + "..."
            
            success_rate = technique['success_rate']
            usage_count = technique['usage_count']
            total_scenarios = technique['total_scenarios']
            confidence = technique['confidence']
            
            # Create progress bar
            bar_length = 12
            filled_length = int(bar_length * success_rate)
            bar = "█" * filled_length + "░" * (bar_length - filled_length)
            
            # Format percentage
            percentage = f"{success_rate * 100:.0f}%"
            
            # Format counts with confidence indicator
            count_str = f"({usage_count}/{total_scenarios})"
            if confidence >= 0.8:
                confidence_indicator = "✅"  # High confidence (8+ examples)
            elif confidence >= 0.6:
                confidence_indicator = "⚠️"   # Medium confidence (3-7 examples)
            else:
                confidence_indicator = "❓"  # Low confidence (1-2 examples)
            
            # Format line
            name_padded = f"{name:<{max_name_length}}"
            line = f"│ {name_padded} {bar} {percentage:>4} {count_str:>10} {confidence_indicator}│"
            report_lines.append(line)
        
        report_lines.append("└" + "─" * 65 + "┘")
        
        # Add legend
        report_lines.append("")
        report_lines.append("Legend: ✅ High confidence  ⚠️ Medium confidence  ❓ Low confidence")
        
        if canonical_scenario:
            # Add scenario-specific insights
            scenario_stats = self.get_canonical_scenario_stats()
            for stat in scenario_stats:
                if stat['canonical_name'] == canonical_scenario:
                    report_lines.append("")
                    report_lines.append(f"📈 Scenario insights:")
                    report_lines.append(f"   • {stat['scenario_count']} writeups analyzed")
                    report_lines.append(f"   • {stat['environment_diversity']} different environments")
                    report_lines.append(f"   • Complexity: {', '.join(stat['complexity_range'])}")
                    report_lines.append(f"   • Data quality: {stat['data_quality']}")
                    break
        
        return "\n".join(report_lines)
    
    def get_environment_success_analysis(self) -> Dict[str, Dict]:
        """Analyze success rates by environment type"""
        
        env_stats = self.db.conn.execute("""
            SELECT 
                s.environment_type,
                t.name as technique,
                AVG(t.success_rate) as avg_success_rate,
                COUNT(*) as usage_count
            FROM scenarios s
            JOIN techniques t ON s.id = t.scenario_id
            WHERE s.environment_type != 'unknown'
            GROUP BY s.environment_type, t.name
            HAVING COUNT(*) >= 2
            ORDER BY s.environment_type, avg_success_rate DESC
        """).fetchall()
        
        environment_analysis = defaultdict(list)
        
        for stat in env_stats:
            env_type = stat['environment_type']
            environment_analysis[env_type].append({
                'technique': stat['technique'],
                'success_rate': stat['avg_success_rate'],
                'usage_count': stat['usage_count']
            })
        
        return dict(environment_analysis)
    
    def get_attack_complexity_analysis(self) -> Dict[str, Dict]:
        """Analyze success rates by attack complexity"""
        
        complexity_stats = self.db.conn.execute("""
            SELECT 
                s.attack_complexity,
                AVG(t.success_rate) as avg_success_rate,
                COUNT(DISTINCT s.id) as scenario_count,
                COUNT(t.id) as technique_count,
                AVG(s.confidence_score) as avg_confidence
            FROM scenarios s
            JOIN techniques t ON s.id = t.scenario_id
            WHERE s.attack_complexity != 'unknown'
            GROUP BY s.attack_complexity
            ORDER BY 
                CASE s.attack_complexity 
                    WHEN 'trivial' THEN 1
                    WHEN 'easy' THEN 2  
                    WHEN 'medium' THEN 3
                    WHEN 'hard' THEN 4
                    WHEN 'very_hard' THEN 5
                    WHEN 'insane' THEN 6
                    ELSE 7
                END
        """).fetchall()
        
        complexity_analysis = {}
        
        for stat in complexity_stats:
            complexity = stat['attack_complexity']
            complexity_analysis[complexity] = {
                'avg_success_rate': stat['avg_success_rate'],
                'scenario_count': stat['scenario_count'],
                'technique_count': stat['technique_count'],
                'avg_confidence': stat['avg_confidence'],
                'difficulty_score': self._get_difficulty_score(complexity)
            }
        
        return complexity_analysis
    
    def generate_comprehensive_report(self) -> str:
        """Generate comprehensive intelligence analysis report"""
        
        report_sections = []
        
        # Overall statistics
        total_scenarios = self.db.conn.execute("SELECT COUNT(*) FROM scenarios").fetchone()[0]
        total_techniques = self.db.conn.execute("SELECT COUNT(*) FROM techniques").fetchone()[0]
        canonical_count = len(self.db.indexes.get('canonical', {}))
        
        report_sections.append("🧠 INTELLIGENCE DATABASE ANALYSIS REPORT")
        report_sections.append("=" * 60)
        report_sections.append(f"📊 Database Overview:")
        report_sections.append(f"   • Total scenarios: {total_scenarios}")
        report_sections.append(f"   • Canonical groups: {canonical_count}")
        report_sections.append(f"   • Total techniques: {total_techniques}")
        report_sections.append(f"   • Port mappings: {len(self.db.indexes.get('ports', {}))}")
        report_sections.append(f"   • Service mappings: {len(self.db.indexes.get('services', {}))}")
        report_sections.append("")
        
        # Top canonical scenarios
        canonical_stats = self.get_canonical_scenario_stats()
        report_sections.append("🎯 TOP ATTACK SCENARIOS:")
        for i, stat in enumerate(canonical_stats[:10], 1):
            name = stat['canonical_name'].replace('_', ' ').title()
            count = stat['scenario_count']
            quality = stat['data_quality']
            report_sections.append(f"  {i:2d}. {name:<40} {count:>3} writeups ({quality} quality)")
        report_sections.append("")
        
        # Environment analysis
        env_analysis = self.get_environment_success_analysis()
        report_sections.append("🌍 SUCCESS RATES BY ENVIRONMENT:")
        for env_type, techniques in list(env_analysis.items())[:5]:
            if techniques:
                best_technique = max(techniques, key=lambda x: x['success_rate'])
                env_name = env_type.replace('_', ' ').title()
                rate = best_technique['success_rate'] * 100
                tech_name = best_technique['technique']
                report_sections.append(f"   {env_name:<25} Best: {tech_name} ({rate:.0f}%)")
        report_sections.append("")
        
        # Complexity analysis  
        complexity_analysis = self.get_attack_complexity_analysis()
        report_sections.append("⚡ SUCCESS RATES BY COMPLEXITY:")
        for complexity, stats in complexity_analysis.items():
            rate = stats['avg_success_rate'] * 100
            count = stats['scenario_count']
            report_sections.append(f"   {complexity.title():<15} {rate:>5.0f}% avg success ({count} scenarios)")
        
        return "\n".join(report_sections)
    
    def _get_total_scenarios(self, canonical_scenario: str = None, environment_type: str = None) -> int:
        """Get total number of scenarios for confidence calculation"""
        
        query = "SELECT COUNT(DISTINCT s.id) FROM scenarios s"
        filters = []
        params = []
        
        if canonical_scenario:
            filters.append("s.canonical_name = ?")
            params.append(canonical_scenario)
        
        if environment_type:
            filters.append("s.environment_type = ?")
            params.append(environment_type)
        
        if filters:
            query += " WHERE " + " AND ".join(filters)
        
        result = self.db.conn.execute(query, params).fetchone()
        return result[0] if result else 0
    
    def _calculate_statistical_confidence(self, usage_count: int, total_scenarios: int, 
                                        min_rate: float, max_rate: float) -> float:
        """Calculate statistical confidence based on sample size and variance"""
        
        # Adjusted thresholds for pentesting data
        # Sample size confidence (more samples = higher confidence)
        if usage_count >= 10:
            sample_confidence = 1.0  # High confidence with 10+ examples
        elif usage_count >= 5:
            sample_confidence = 0.8  # Medium-high confidence with 5-9 examples
        elif usage_count >= 3:
            sample_confidence = 0.6  # Medium confidence with 3-4 examples
        elif usage_count >= 2:
            sample_confidence = 0.4  # Low-medium confidence with 2 examples
        else:
            sample_confidence = 0.2  # Low confidence with 1 example
        
        # Variance confidence (less variance = higher confidence)
        variance = max_rate - min_rate
        if variance <= 0.1:  # Very consistent results
            variance_confidence = 1.0
        elif variance <= 0.2:  # Fairly consistent
            variance_confidence = 0.8
        elif variance <= 0.3:  # Some variation
            variance_confidence = 0.6
        else:  # High variation
            variance_confidence = 0.4
        
        # Combined confidence (weighted toward sample size for pentesting)
        combined_confidence = (sample_confidence * 0.8) + (variance_confidence * 0.2)
        
        return combined_confidence
    
    def _assess_data_quality(self, scenario_count: int, avg_confidence: float) -> str:
        """Assess data quality based on scenario count and confidence"""
        
        if scenario_count >= 10 and avg_confidence >= 0.8:
            return "excellent"
        elif scenario_count >= 5 and avg_confidence >= 0.7:
            return "good"
        elif scenario_count >= 3 and avg_confidence >= 0.6:
            return "fair"
        else:
            return "limited"
    
    def _get_difficulty_score(self, complexity: str) -> int:
        """Convert complexity to numeric difficulty score"""
        
        difficulty_map = {
            'trivial': 1,
            'easy': 2,
            'medium': 3, 
            'hard': 4,
            'very_hard': 5,
            'insane': 6
        }
        return difficulty_map.get(complexity.lower(), 3)

class IntelligenceReporting:
    """Advanced reporting and visualization"""
    
    def __init__(self, analytics: IntelligenceAnalytics):
        self.analytics = analytics
    
    def generate_scenario_dashboard(self, canonical_scenario: str) -> str:
        """Generate comprehensive dashboard for a scenario"""
        
        # Get scenario statistics
        scenario_stats = self.analytics.get_canonical_scenario_stats()
        target_stat = None
        for stat in scenario_stats:
            if stat['canonical_name'] == canonical_scenario:
                target_stat = stat
                break
        
        if not target_stat:
            return f"No data found for scenario: {canonical_scenario}"
        
        # Get technique success rates
        techniques = self.analytics.get_technique_success_rates(canonical_scenario)
        
        # Generate dashboard
        dashboard_lines = []
        
        # Header
        scenario_display = canonical_scenario.replace('_', ' ').title()
        dashboard_lines.append(f"🎯 {scenario_display.upper()} - ATTACK INTELLIGENCE DASHBOARD")
        dashboard_lines.append("=" * 80)
        
        # Overview section
        dashboard_lines.append("📊 SCENARIO OVERVIEW:")
        dashboard_lines.append(f"   • Total writeups analyzed: {target_stat['scenario_count']}")
        dashboard_lines.append(f"   • Environment diversity: {target_stat['environment_diversity']} types")
        dashboard_lines.append(f"   • OS diversity: {target_stat['os_diversity']} families")
        dashboard_lines.append(f"   • Complexity range: {', '.join(target_stat['complexity_range'])}")
        dashboard_lines.append(f"   • Data quality: {target_stat['data_quality'].upper()}")
        dashboard_lines.append("")
        
        # Top techniques section
        dashboard_lines.append("🔧 TOP ATTACK TECHNIQUES:")
        if techniques:
            for i, tech in enumerate(techniques[:8], 1):
                name = tech['technique'][:40] + "..." if len(tech['technique']) > 40 else tech['technique']
                rate = tech['success_rate'] * 100
                confidence_emoji = "✅" if tech['confidence'] > 0.8 else "⚠️" if tech['confidence'] > 0.5 else "❓"
                dashboard_lines.append(f"   {i:2d}. {name:<45} {rate:>5.0f}% {confidence_emoji}")
        else:
            dashboard_lines.append("   No technique data available")
        dashboard_lines.append("")
        
        # Success rate visualization
        dashboard_lines.append("📈 SUCCESS RATE ANALYSIS:")
        if techniques:
            # Calculate statistics
            rates = [t['success_rate'] for t in techniques]
            avg_rate = sum(rates) / len(rates)
            max_rate = max(rates)
            min_rate = min(rates)
            
            dashboard_lines.append(f"   • Average success rate: {avg_rate * 100:.1f}%")
            dashboard_lines.append(f"   • Best technique: {max_rate * 100:.1f}%")
            dashboard_lines.append(f"   • Worst technique: {min_rate * 100:.1f}%")
            dashboard_lines.append(f"   • Technique count: {len(techniques)}")
        dashboard_lines.append("")
        
        # Time estimates
        dashboard_lines.append("⏱️ ESTIMATED ATTACK TIMELINE:")
        complexity_analysis = self.analytics.get_attack_complexity_analysis()
        for complexity in target_stat['complexity_range']:
            if complexity in complexity_analysis:
                stats = complexity_analysis[complexity]
                rate = stats['avg_success_rate'] * 100
                dashboard_lines.append(f"   • {complexity.title():<12} ~{rate:.0f}% success rate")
        dashboard_lines.append("")
        
        # Environment analysis
        env_analysis = self.analytics.get_environment_success_analysis()
        dashboard_lines.append("🌍 ENVIRONMENT-SPECIFIC INSIGHTS:")
        found_envs = 0
        for env_type, env_techniques in env_analysis.items():
            if any(canonical_scenario in t.get('scenario', '') for t in env_techniques):
                if found_envs < 3:  # Limit to top 3
                    best_tech = max(env_techniques, key=lambda x: x['success_rate'])
                    env_display = env_type.replace('_', ' ').title()
                    rate = best_tech['success_rate'] * 100
                    dashboard_lines.append(f"   • {env_display:<20} Best: {best_tech['technique']} ({rate:.0f}%)")
                    found_envs += 1
        
        if found_envs == 0:
            dashboard_lines.append("   No environment-specific data available")
        
        return "\n".join(dashboard_lines)
    
    def generate_comparative_analysis(self, scenario_list: List[str]) -> str:
        """Generate comparative analysis between multiple scenarios"""
        
        if len(scenario_list) < 2:
            return "Need at least 2 scenarios for comparison"
        
        comparison_lines = []
        comparison_lines.append("🔄 SCENARIO COMPARISON ANALYSIS")
        comparison_lines.append("=" * 60)
        
        # Get data for all scenarios
        scenario_data = {}
        for scenario in scenario_list:
            techniques = self.analytics.get_technique_success_rates(scenario)
            scenario_data[scenario] = {
                'techniques': techniques,
                'avg_success_rate': sum(t['success_rate'] for t in techniques) / len(techniques) if techniques else 0,
                'technique_count': len(techniques)
            }
        
        # Overview comparison
        comparison_lines.append("📊 OVERVIEW COMPARISON:")
        for scenario in scenario_list:
            data = scenario_data[scenario]
            display_name = scenario.replace('_', ' ').title()
            avg_rate = data['avg_success_rate'] * 100
            count = data['technique_count']
            comparison_lines.append(f"   {display_name:<35} {avg_rate:>5.1f}% avg ({count} techniques)")
        comparison_lines.append("")
        
        # Best techniques comparison
        comparison_lines.append("🏆 BEST TECHNIQUES COMPARISON:")
        for scenario in scenario_list:
            data = scenario_data[scenario]
            if data['techniques']:
                best_tech = data['techniques'][0]  # Already sorted by success rate
                display_name = scenario.replace('_', ' ').title()
                rate = best_tech['success_rate'] * 100
                tech_name = best_tech['technique'][:30]
                comparison_lines.append(f"   {display_name:<20} {tech_name:<32} {rate:>5.1f}%")
        comparison_lines.append("")
        
        # Difficulty comparison
        comparison_lines.append("⚡ DIFFICULTY RANKING:")
        complexity_scores = {}
        for scenario in scenario_list:
            # Get complexity data for this scenario
            scenario_stats = self.analytics.get_canonical_scenario_stats()
            for stat in scenario_stats:
                if stat['canonical_name'] == scenario:
                    complexities = stat['complexity_range']
                    if complexities:
                        # Calculate average difficulty
                        difficulty_map = {'trivial': 1, 'easy': 2, 'medium': 3, 'hard': 4, 'very_hard': 5, 'insane': 6}
                        scores = [difficulty_map.get(c.lower(), 3) for c in complexities]
                        complexity_scores[scenario] = sum(scores) / len(scores)
                    break
        
        # Sort by difficulty
        sorted_scenarios = sorted(complexity_scores.items(), key=lambda x: x[1])
        for i, (scenario, score) in enumerate(sorted_scenarios, 1):
            display_name = scenario.replace('_', ' ').title()
            difficulty_names = ['Trivial', 'Easy', 'Medium', 'Hard', 'Very Hard', 'Insane']
            difficulty = difficulty_names[min(int(score) - 1, 5)]
            comparison_lines.append(f"   {i}. {display_name:<35} {difficulty}")
        
        return "\n".join(comparison_lines)
    
    def generate_attack_timeline_report(self, canonical_scenario: str) -> str:
        """Generate detailed attack timeline and phases"""
        
        techniques = self.analytics.get_technique_success_rates(canonical_scenario)
        if not techniques:
            return f"No technique data available for {canonical_scenario}"
        
        timeline_lines = []
        scenario_display = canonical_scenario.replace('_', ' ').title()
        timeline_lines.append(f"⏱️ {scenario_display.upper()} - ATTACK TIMELINE & PHASES")
        timeline_lines.append("=" * 70)
        
        # Phase categorization
        phases = {
            'reconnaissance': [],
            'initial_access': [],
            'privilege_escalation': [],
            'persistence': [],
            'lateral_movement': []
        }
        
        # Categorize techniques by phase (simplified)
        for tech in techniques:
            tech_name_lower = tech['technique'].lower()
            if any(word in tech_name_lower for word in ['scan', 'enum', 'discovery', 'recon']):
                phases['reconnaissance'].append(tech)
            elif any(word in tech_name_lower for word in ['shell', 'exploit', 'injection', 'upload']):
                phases['initial_access'].append(tech)
            elif any(word in tech_name_lower for word in ['escalation', 'privilege', 'sudo', 'admin']):
                phases['privilege_escalation'].append(tech)
            elif any(word in tech_name_lower for word in ['persistence', 'backdoor', 'cron', 'service']):
                phases['persistence'].append(tech)
            elif any(word in tech_name_lower for word in ['lateral', 'movement', 'pivot', 'tunnel']):
                phases['lateral_movement'].append(tech)
            else:
                phases['initial_access'].append(tech)  # Default to initial access
        
        # Generate timeline
        phase_order = ['reconnaissance', 'initial_access', 'privilege_escalation', 'persistence', 'lateral_movement']
        phase_names = ['🔍 Reconnaissance', '🚪 Initial Access', '⬆️ Privilege Escalation', '🔒 Persistence', '↔️ Lateral Movement']
        
        for phase_key, phase_name in zip(phase_order, phase_names):
            if phases[phase_key]:
                timeline_lines.append(f"\n{phase_name}:")
                
                # Sort by success rate
                sorted_techniques = sorted(phases[phase_key], key=lambda x: x['success_rate'], reverse=True)
                
                for i, tech in enumerate(sorted_techniques[:5], 1):  # Top 5 per phase
                    name = tech['technique'][:45]
                    rate = tech['success_rate'] * 100
                    confidence = "✅" if tech['confidence'] > 0.8 else "⚠️" if tech['confidence'] > 0.5 else "❓"
                    timeline_lines.append(f"   {i}. {name:<47} {rate:>5.1f}% {confidence}")
        
        # Time estimates
        timeline_lines.append(f"\n⏱️ ESTIMATED TIMELINE:")
        timeline_lines.append(f"   • Reconnaissance: 15-45 minutes")
        timeline_lines.append(f"   • Initial Access: 30 minutes - 2 hours")
        timeline_lines.append(f"   • Privilege Escalation: 15 minutes - 1 hour")
        timeline_lines.append(f"   • Persistence: 10-30 minutes")
        timeline_lines.append(f"   • Lateral Movement: 30 minutes - 2+ hours")
        
        # Overall success prediction
        if techniques:
            overall_rate = sum(t['success_rate'] for t in techniques) / len(techniques)
            timeline_lines.append(f"\n🎯 OVERALL SUCCESS PREDICTION: {overall_rate * 100:.1f}%")
            
            if overall_rate > 0.8:
                timeline_lines.append("   ✅ HIGH likelihood of success")
            elif overall_rate > 0.6:
                timeline_lines.append("   ⚠️ MEDIUM likelihood of success")
            else:
                timeline_lines.append("   ❌ LOW likelihood of success - consider alternative approaches")
        
        return "\n".join(timeline_lines)