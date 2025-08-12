import os
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
import openai
import anthropic

@dataclass
class ComparisonConfig:
    """Configuration for model comparison testing with Claude 4"""
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    test_writeups: int = 5  # Test 5 of each model
    output_dir: str = "model_comparison"
    delay_between_requests: float = 2.0  # Claude 4: 50 RPM, OpenAI: 3 RPM

class ModelComparisonExtractor:
    """Compare Claude 4 vs GPT-4o for intelligence extraction quality"""
    
    def __init__(self, config: ComparisonConfig):
        self.config = config
        
        # Initialize API clients
        openai.api_key = config.openai_api_key
        self.anthropic_client = anthropic.Anthropic(api_key=config.anthropic_api_key)
        
        self.comparison_results = {
            "claude": {"successes": 0, "failures": 0, "extractions": []},
            "gpt4o": {"successes": 0, "failures": 0, "extractions": []},
            "quality_comparison": {}
        }
    
    def _extract_json_from_response(self, content: str) -> str:
        """Extract JSON from Claude response that might contain extra text"""
        
        # Try to find JSON block markers
        if '```json' in content:
            start = content.find('```json') + 7
            end = content.find('```', start)
            if end != -1:
                return content[start:end].strip()
        
        # Try to find JSON object by looking for opening brace
        start_brace = content.find('{')
        if start_brace == -1:
            return content  # No JSON found, return as-is
        
        # Find the matching closing brace
        brace_count = 0
        for i in range(start_brace, len(content)):
            if content[i] == '{':
                brace_count += 1
            elif content[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    return content[start_brace:i+1]
        
        # If we can't find a complete JSON object, return from first brace to end
        return content[start_brace:].strip()
    
    def extract_with_claude(self, writeup_text: str, filename: str) -> Dict:
        """Extract intelligence using Claude Sonnet 4"""
        
        prompt = f"""
        You are analyzing a penetration testing writeup to extract actionable intelligence.
        Extract a comprehensive scenario fingerprint and success patterns.

        CRITICAL: Return ONLY the JSON object below with no additional text, explanations, or markdown formatting.

        {{
            "scenario_fingerprint": {{
                "scenario_name": "descriptive_name_of_attack_scenario",
                "primary_services": ["service1", "service2"],
                "port_signature": "port1+port2+port3",
                "os_family": "windows/linux",
                "environment_type": "active_directory/web_app/database",
                "entry_vector": "main_attack_method",
                "privilege_path": "escalation_method",
                "attack_complexity": "easy/medium/hard",
                "estimated_time": "time_range",
                "scenario_confidence": 0.0
            }},
            "success_patterns": {{
                "primary_technique": {{
                    "technique": "technique_name",
                    "success_reason": "why_it_worked",
                    "success_probability": 0.0,
                    "recognition_signs": ["sign1", "sign2"],
                    "prerequisites": ["prereq1", "prereq2"]
                }},
                "key_discovery": {{
                    "discovery": "what_was_found",
                    "discovery_method": "how_found",
                    "why_critical": "impact_explanation"
                }}
            }},
            "technique_commands": [
                {{
                    "command": "actual_command_used",
                    "tool": "tool_name", 
                    "purpose": "what_it_does",
                    "success_indicator": "expected_output"
                }}
            ],
            "applicability_rules": {{
                "when_applicable": ["condition1", "condition2"],
                "success_indicators": ["indicator1", "indicator2"],
                "failure_modes": ["failure1", "failure2"]
            }}
        }}

        Filename: {filename}
        
        Writeup text to analyze:
        {writeup_text[:12000]}
        """
        
        try:
            response = self.anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",  # 🚀 CLAUDE 4 SONNET - Latest model
                max_tokens=4096,  # Increased for better extraction
                temperature=0.1,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            content = response.content[0].text.strip()
            
            # Enhanced JSON extraction for Claude responses
            content = self._extract_json_from_response(content)
            
            # Parse JSON response
            return json.loads(content)
            
        except Exception as e:
            print(f"  ❌ Claude 4 API error: {e}")
            return {"error": str(e)}
    
    def extract_with_gpt4o(self, writeup_text: str, filename: str) -> Dict:
        """Extract intelligence using GPT-4o"""
        
        prompt = f"""
        You are analyzing a penetration testing writeup to extract actionable intelligence.
        Extract a comprehensive scenario fingerprint and success patterns.

        Return ONLY valid JSON in this exact format:
        {{
            "scenario_fingerprint": {{
                "scenario_name": "descriptive_name_of_attack_scenario",
                "primary_services": ["service1", "service2"],
                "port_signature": "port1+port2+port3",
                "os_family": "windows/linux",
                "environment_type": "active_directory/web_app/database",
                "entry_vector": "main_attack_method",
                "privilege_path": "escalation_method",
                "attack_complexity": "easy/medium/hard",
                "estimated_time": "time_range",
                "scenario_confidence": 0.0
            }},
            "success_patterns": {{
                "primary_technique": {{
                    "technique": "technique_name",
                    "success_reason": "why_it_worked",
                    "success_probability": 0.0,
                    "recognition_signs": ["sign1", "sign2"],
                    "prerequisites": ["prereq1", "prereq2"]
                }},
                "key_discovery": {{
                    "discovery": "what_was_found",
                    "discovery_method": "how_found",
                    "why_critical": "impact_explanation"
                }}
            }},
            "technique_commands": [
                {{
                    "command": "actual_command_used",
                    "tool": "tool_name", 
                    "purpose": "what_it_does",
                    "success_indicator": "expected_output"
                }}
            ],
            "applicability_rules": {{
                "when_applicable": ["condition1", "condition2"],
                "success_indicators": ["indicator1", "indicator2"],
                "failure_modes": ["failure1", "failure2"]
            }}
        }}

        Filename: {filename}
        
        Writeup text to analyze:
        {writeup_text[:12000]}
        """
        
        try:
            # Updated for new OpenAI API
            client = openai.OpenAI(api_key=self.config.openai_api_key)
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert. Return only valid JSON that can be parsed."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=4096
            )
            
            content = response.choices[0].message.content.strip()
            
            # Clean and parse JSON
            if content.startswith('```json'):
                content = content.replace('```json', '').replace('```', '').strip()
            
            return json.loads(content)
            
        except Exception as e:
            print(f"  ❌ GPT-4o extraction failed: {e}")
            return {"error": str(e)}
    
    def evaluate_extraction_quality(self, extraction: Dict, original_text: str, model_name: str) -> Dict:
        """Evaluate the quality of an extraction"""
        
        quality_scores = {
            "completeness": 0.0,
            "accuracy": 0.0, 
            "actionability": 0.0,
            "specificity": 0.0,
            "overall": 0.0
        }
        
        if "error" in extraction:
            return quality_scores
        
        # Check completeness (all required fields present)
        required_sections = ["scenario_fingerprint", "success_patterns", "technique_commands", "applicability_rules"]
        present_sections = sum(1 for section in required_sections if section in extraction and extraction[section])
        quality_scores["completeness"] = present_sections / len(required_sections)
        
        # Check scenario fingerprint quality
        scenario = extraction.get("scenario_fingerprint", {})
        scenario_fields = ["scenario_name", "primary_services", "port_signature", "environment_type"]
        scenario_quality = sum(1 for field in scenario_fields if scenario.get(field))
        quality_scores["specificity"] = scenario_quality / len(scenario_fields)
        
        # Check success patterns depth
        patterns = extraction.get("success_patterns", {})
        if patterns and patterns.get("primary_technique"):
            technique = patterns["primary_technique"]
            pattern_quality = sum(1 for field in ["technique", "success_reason", "prerequisites"] if technique.get(field))
            quality_scores["actionability"] = pattern_quality / 3
        
        # Check command extraction
        commands = extraction.get("technique_commands", [])
        if commands and len(commands) > 0:
            command_quality = sum(1 for cmd in commands if cmd.get("command") and cmd.get("tool"))
            quality_scores["accuracy"] = min(command_quality / len(commands), 1.0)
        
        # Calculate overall score
        quality_scores["overall"] = sum(quality_scores.values()) / len([k for k in quality_scores.keys() if k != "overall"])
        
        return quality_scores
    
    def compare_models(self, writeups_dir: str):
        """Run the comparison test between Claude 4 and GPT-4o on the SAME writeups"""
        
        output_path = Path(self.config.output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Get writeup files - both models will test the SAME files
        writeups_path = Path(writeups_dir)
        md_files = list(writeups_path.glob("*.md"))[:self.config.test_writeups]
        
        if len(md_files) < self.config.test_writeups:
            print(f"⚠️ Only found {len(md_files)} writeups, adjusting test size")
            self.config.test_writeups = len(md_files)
        
        print(f"🧪 Model Comparison Test - Claude 4 vs GPT-4o")
        print(f"📊 Testing SAME {self.config.test_writeups} writeups with both models")
        print(f"🤖 Models: Claude Sonnet 4 vs GPT-4o")
        print(f"📝 Writeups: {[f.name for f in md_files]}")
        print(f"💰 Estimated cost: ~$8-12 total")
        print(f"⏱️ Estimated time: ~15-20 minutes")
        print()
        
        if input("Continue with comparison? (y/n): ").lower() != 'y':
            return
        
        start_time = time.time()
        
        # Test Claude 4 on the writeups
        print(f"\n🔵 Testing Claude Sonnet 4 on {self.config.test_writeups} writeups...")
        
        for i, writeup_file in enumerate(md_files, 1):
            print(f"  [{i}/{self.config.test_writeups}] Claude 4 processing {writeup_file.name}...")
            
            # Read writeup
            content = self._read_writeup(writeup_file)
            
            # Extract with Claude 4
            claude_result = self.extract_with_claude(content, writeup_file.name)
            
            # Evaluate quality
            quality = self.evaluate_extraction_quality(claude_result, content, "claude")
            
            # Store result
            result_data = {
                "writeup": writeup_file.name,
                "extraction": claude_result,
                "quality_scores": quality,
                "model": "claude-sonnet-4",
                "timestamp": datetime.now().isoformat()
            }
            
            self.comparison_results["claude"]["extractions"].append(result_data)
            
            if "error" not in claude_result:
                self.comparison_results["claude"]["successes"] += 1
                print(f"    ✅ Success - Quality: {quality['overall']:.2f}")
            else:
                self.comparison_results["claude"]["failures"] += 1
                print(f"    ❌ Failed - Error: {claude_result.get('error', 'Unknown')[:50]}...")
            
            # Save individual result
            with open(output_path / f"claude4_{writeup_file.stem}.json", 'w') as f:
                json.dump(result_data, f, indent=2)
            
            time.sleep(self.config.delay_between_requests)
        
        # Test GPT-4o on the SAME writeups  
        print(f"\n🟠 Testing GPT-4o on the SAME {self.config.test_writeups} writeups...")
        
        for i, writeup_file in enumerate(md_files, 1):
            print(f"  [{i}/{self.config.test_writeups}] GPT-4o processing {writeup_file.name}...")
            
            # Read the SAME writeup
            content = self._read_writeup(writeup_file)
            
            # Extract with GPT-4o
            gpt_result = self.extract_with_gpt4o(content, writeup_file.name)
            
            # Evaluate quality
            quality = self.evaluate_extraction_quality(gpt_result, content, "gpt4o")
            
            # Store result
            result_data = {
                "writeup": writeup_file.name,
                "extraction": gpt_result,
                "quality_scores": quality,
                "model": "gpt-4o",
                "timestamp": datetime.now().isoformat()
            }
            
            self.comparison_results["gpt4o"]["extractions"].append(result_data)
            
            if "error" not in gpt_result:
                self.comparison_results["gpt4o"]["successes"] += 1
                print(f"    ✅ Success - Quality: {quality['overall']:.2f}")
            else:
                self.comparison_results["gpt4o"]["failures"] += 1
                print(f"    ❌ Failed - Error: {gpt_result.get('error', 'Unknown')[:50]}...")
            
            # Save individual result
            with open(output_path / f"gpt4o_{writeup_file.stem}.json", 'w') as f:
                json.dump(result_data, f, indent=2)
            
            time.sleep(self.config.delay_between_requests)
        
        # Generate head-to-head comparison report
        self._generate_comparison_report(output_path, time.time() - start_time)
    
    def _read_writeup(self, writeup_file: Path) -> str:
        """Read and clean writeup content"""
        with open(writeup_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract content after frontmatter
        if content.startswith('---'):
            parts = content.split('---', 2)
            if len(parts) >= 3:
                return parts[2]
        
        return content
    
    def _generate_comparison_report(self, output_path: Path, elapsed_time: float):
        """Generate detailed head-to-head comparison report"""
        
        print(f"\n📊 Generating head-to-head comparison report...")
        
        # Calculate average quality scores
        claude_scores = [ext["quality_scores"] for ext in self.comparison_results["claude"]["extractions"]]
        gpt_scores = [ext["quality_scores"] for ext in self.comparison_results["gpt4o"]["extractions"]]
        
        claude_avg = self._average_scores(claude_scores)
        gpt_avg = self._average_scores(gpt_scores)
        
        # Generate writeup-by-writeup comparison
        writeup_comparisons = []
        for i in range(self.config.test_writeups):
            if i < len(self.comparison_results["claude"]["extractions"]) and i < len(self.comparison_results["gpt4o"]["extractions"]):
                claude_result = self.comparison_results["claude"]["extractions"][i]
                gpt_result = self.comparison_results["gpt4o"]["extractions"][i]
                
                writeup_comparisons.append({
                    "writeup": claude_result["writeup"],
                    "claude_quality": claude_result["quality_scores"]["overall"],
                    "gpt4o_quality": gpt_result["quality_scores"]["overall"],
                    "winner": "claude" if claude_result["quality_scores"]["overall"] > gpt_result["quality_scores"]["overall"] else "gpt4o",
                    "margin": abs(claude_result["quality_scores"]["overall"] - gpt_result["quality_scores"]["overall"])
                })
        
        # Count individual writeup wins
        claude_wins = sum(1 for comp in writeup_comparisons if comp["winner"] == "claude")
        gpt_wins = sum(1 for comp in writeup_comparisons if comp["winner"] == "gpt4o")
        
        # Generate report
        report = {
            "comparison_summary": {
                "test_date": datetime.now().isoformat(),
                "writeups_tested": self.config.test_writeups,
                "same_writeups_both_models": True,
                "total_processing_time_minutes": elapsed_time / 60,
                "models_tested": ["claude-sonnet-4", "gpt-4o"]
            },
            "head_to_head_results": {
                "claude_wins": claude_wins,
                "gpt4o_wins": gpt_wins,
                "writeup_comparisons": writeup_comparisons
            },
            "aggregate_results": {
                "claude": {
                    "successes": self.comparison_results["claude"]["successes"],
                    "failures": self.comparison_results["claude"]["failures"],
                    "success_rate": self.comparison_results["claude"]["successes"] / self.config.test_writeups,
                    "average_quality_scores": claude_avg
                },
                "gpt4o": {
                    "successes": self.comparison_results["gpt4o"]["successes"],
                    "failures": self.comparison_results["gpt4o"]["failures"],
                    "success_rate": self.comparison_results["gpt4o"]["successes"] / self.config.test_writeups,
                    "average_quality_scores": gpt_avg
                }
            },
            "winner_analysis": self._determine_winner(claude_avg, gpt_avg, claude_wins, gpt_wins),
            "recommendations": self._generate_recommendations(claude_avg, gpt_avg, claude_wins, gpt_wins)
        }
        
        # Save comprehensive report
        with open(output_path / "claude4_vs_gpt4o_comparison.json", 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        self._print_comparison_summary(report)
    
    def _average_scores(self, score_list: List[Dict]) -> Dict:
        """Calculate average quality scores"""
        if not score_list:
            return {}
        
        avg_scores = {}
        for key in score_list[0].keys():
            avg_scores[key] = sum(scores[key] for scores in score_list) / len(score_list)
        
        return avg_scores
    
    def _determine_winner(self, claude_avg: Dict, gpt_avg: Dict, claude_wins: int, gpt_wins: int) -> Dict:
        """Determine which model performed better using multiple criteria"""
        
        if not claude_avg or not gpt_avg:
            return {"winner": "inconclusive", "reason": "insufficient_data"}
        
        claude_overall = claude_avg.get("overall", 0)
        gpt_overall = gpt_avg.get("overall", 0)
        
        # Multiple criteria for determining winner
        criteria = {
            "average_quality": claude_overall > gpt_overall,
            "head_to_head_wins": claude_wins > gpt_wins,
            "significant_margin": abs(claude_overall - gpt_overall) > 0.05
        }
        
        if criteria["average_quality"] and criteria["head_to_head_wins"]:
            return {
                "winner": "claude",
                "quality_margin": claude_overall - gpt_overall,
                "head_to_head": f"{claude_wins}-{gpt_wins}",
                "reason": "won_both_average_quality_and_head_to_head"
            }
        elif not criteria["average_quality"] and not criteria["head_to_head_wins"]:
            return {
                "winner": "gpt4o",
                "quality_margin": gpt_overall - claude_overall,
                "head_to_head": f"{gpt_wins}-{claude_wins}",
                "reason": "won_both_average_quality_and_head_to_head"
            }
        elif criteria["significant_margin"]:
            winner = "claude" if claude_overall > gpt_overall else "gpt4o"
            return {
                "winner": winner,
                "quality_margin": abs(claude_overall - gpt_overall),
                "head_to_head": f"{claude_wins}-{gpt_wins}",
                "reason": "significant_quality_difference_overrides_head_to_head"
            }
        else:
            return {
                "winner": "tie",
                "quality_margin": abs(claude_overall - gpt_overall),
                "head_to_head": f"{claude_wins}-{gpt_wins}",
                "reason": "mixed_results_no_clear_winner"
            }
    
    def _generate_recommendations(self, claude_avg: Dict, gpt_avg: Dict, claude_wins: int, gpt_wins: int) -> Dict:
        """Generate recommendations based on head-to-head comparison"""
        
        recommendations = {
            "for_full_extraction": "",
            "cost_consideration": "",
            "quality_consideration": "",
            "speed_consideration": "",
            "confidence_level": ""
        }
        
        if not claude_avg or not gpt_avg:
            recommendations["for_full_extraction"] = "Rerun comparison with more samples"
            return recommendations
        
        claude_overall = claude_avg.get("overall", 0)
        gpt_overall = gpt_avg.get("overall", 0)
        
        # Quality difference analysis
        quality_diff = abs(claude_overall - gpt_overall)
        
        if claude_overall > gpt_overall and claude_wins >= gpt_wins:
            recommendations["for_full_extraction"] = "Use Claude 4 for full 500 writeup extraction"
            recommendations["quality_consideration"] = f"Claude 4 superior: {claude_overall:.2f} vs {gpt_overall:.2f} quality, won {claude_wins}/{self.config.test_writeups} head-to-head"
            recommendations["confidence_level"] = "High" if quality_diff > 0.1 else "Medium"
        elif gpt_overall > claude_overall and gpt_wins >= claude_wins:
            recommendations["for_full_extraction"] = "Use GPT-4o for full extraction"  
            recommendations["quality_consideration"] = f"GPT-4o superior: {gpt_overall:.2f} vs {claude_overall:.2f} quality, won {gpt_wins}/{self.config.test_writeups} head-to-head"
            recommendations["confidence_level"] = "High" if quality_diff > 0.1 else "Medium"
        else:
            recommendations["for_full_extraction"] = "Either model acceptable - consider cost/speed trade-offs"
            recommendations["quality_consideration"] = f"Mixed results: Claude 4 {claude_overall:.2f} vs GPT-4o {gpt_overall:.2f}, head-to-head {claude_wins}-{gpt_wins}"
            recommendations["confidence_level"] = "Low - consider testing more writeups"
        
        recommendations["cost_consideration"] = "Claude 4 ~$100-150 vs GPT-4o ~$50-75 for 500 writeups"
        recommendations["speed_consideration"] = "Claude 4: 50 RPM vs GPT-4o: 10 RPM (Claude 4 is 5x faster)"
        
        return recommendations
    
    def _print_comparison_summary(self, report: Dict):
        """Print a detailed head-to-head comparison summary"""
        
        print(f"\n🎯 CLAUDE 4 vs GPT-4o HEAD-TO-HEAD COMPARISON")
        print(f"=" * 60)
        
        claude_results = report["aggregate_results"]["claude"]
        gpt_results = report["aggregate_results"]["gpt4o"]
        head_to_head = report["head_to_head_results"]
        
        print(f"\n📝 TESTED ON SAME {self.config.test_writeups} WRITEUPS:")
        for comp in head_to_head["writeup_comparisons"]:
            winner_symbol = "🔵" if comp["winner"] == "claude" else "🟠"
            print(f"  {winner_symbol} {comp['writeup']:<30} Claude 4: {comp['claude_quality']:.2f} | GPT-4o: {comp['gpt4o_quality']:.2f}")
        
        print(f"\n🏆 HEAD-TO-HEAD WINS:")
        print(f"  Claude 4: {head_to_head['claude_wins']}/{self.config.test_writeups}")
        print(f"  GPT-4o:   {head_to_head['gpt4o_wins']}/{self.config.test_writeups}")
        
        print(f"\n📈 SUCCESS RATES:")
        print(f"  Claude 4: {claude_results['success_rate']:.1%} ({claude_results['successes']}/{self.config.test_writeups})")
        print(f"  GPT-4o:   {gpt_results['success_rate']:.1%} ({gpt_results['successes']}/{self.config.test_writeups})")
        
        print(f"\n📊 AVERAGE QUALITY SCORES:")
        claude_quality = claude_results['average_quality_scores']
        gpt_quality = gpt_results['average_quality_scores']
        
        print(f"  Completeness:  Claude 4 {claude_quality.get('completeness', 0):.2f} | GPT-4o {gpt_quality.get('completeness', 0):.2f}")
        print(f"  Accuracy:      Claude 4 {claude_quality.get('accuracy', 0):.2f} | GPT-4o {gpt_quality.get('accuracy', 0):.2f}")
        print(f"  Actionability: Claude 4 {claude_quality.get('actionability', 0):.2f} | GPT-4o {gpt_quality.get('actionability', 0):.2f}")
        print(f"  Specificity:   Claude 4 {claude_quality.get('specificity', 0):.2f} | GPT-4o {gpt_quality.get('specificity', 0):.2f}")
        print(f"  OVERALL:       Claude 4 {claude_quality.get('overall', 0):.2f} | GPT-4o {gpt_quality.get('overall', 0):.2f}")
        
        winner = report["winner_analysis"]
        print(f"\n🏆 FINAL WINNER: {winner['winner'].upper()}")
        if winner['winner'] != 'tie':
            print(f"   Quality Margin: {winner['quality_margin']:.3f}")
            print(f"   Head-to-Head: {winner['head_to_head']}")
        print(f"   Reason: {winner['reason'].replace('_', ' ').title()}")
        
        print(f"\n💡 RECOMMENDATION:")
        recommendations = report['recommendations']
        print(f"   {recommendations['for_full_extraction']}")
        print(f"   Quality: {recommendations['quality_consideration']}")
        print(f"   Confidence: {recommendations['confidence_level']}")
        print(f"   Cost: {recommendations['cost_consideration']}")
        print(f"   Speed: {recommendations['speed_consideration']}")
        
        print(f"\n📁 Detailed results saved to: {self.config.output_dir}/claude4_vs_gpt4o_comparison.json")

# Usage
if __name__ == "__main__":
    config = ComparisonConfig(
        openai_api_key="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",      # SET YOUR ACTUAL API KEYS
        anthropic_api_key="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", # SET YOUR ACTUAL API KEYS
        test_writeups=5,
        output_dir="model_comparison"
    )
    
    extractor = ModelComparisonExtractor(config)
    extractor.compare_models("0xdf_writeups")