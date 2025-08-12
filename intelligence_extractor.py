import os
import json
import re
import time
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import anthropic
from concurrent.futures import ThreadPoolExecutor, as_completed

@dataclass
class IntelligenceConfig:
    """Configuration for intelligence extraction with Claude 4"""
    anthropic_api_key: str = ""  # Set your Anthropic API key
    model: str = "claude-sonnet-4-20250514"  # Claude Sonnet 4
    max_retries: int = 3
    delay_between_requests: float = 1.5  # Claude has higher rate limits
    confidence_threshold: float = 0.7
    max_workers: int = 2  # Claude can handle more concurrent requests
    batch_size: int = 50  # Larger batches due to better rate limits
    rate_limit_buffer: float = 0.5  # Less buffer needed
    
class IntelligenceExtractor:
    """Complete intelligence extraction system for pentesting writeups using Claude 4"""
    
    def __init__(self, config: IntelligenceConfig):
        self.config = config
        self.anthropic_client = anthropic.Anthropic(api_key=config.anthropic_api_key)
        self.processed_count = 0
        self.failed_extractions = []
        self.low_confidence_cases = []
        self.extraction_stats = {
            'total_processed': 0,
            'scenario_fingerprints': 0,
            'success_patterns': 0,
            'decision_trees': 0,
            'applicability_rules': 0,
            'technique_extractions': 0
        }
        
    def extract_scenario_fingerprint(self, writeup_text: str, filename: str) -> Dict:
        """Extract the unique fingerprint that identifies this attack scenario"""
        
        prompt = f"""
        You are analyzing a penetration testing writeup to extract a SCENARIO FINGERPRINT.
        This fingerprint will be used to match similar attack scenarios in real-time.

        Extract the unique combination that defines this scenario for practical field use.
        Focus on what a pentester would need to recognize this scenario in the wild.

        Return ONLY valid JSON:
        {{
            "scenario_name": "windows_domain_controller_asreproast",
            "primary_services": ["kerberos", "ldap", "smb", "dns"],
            "port_signature": "53+88+389+445",
            "service_combination": "dns+kerberos+ldap+smb",
            "os_family": "windows_server",
            "environment_type": "active_directory",
            "entry_vector": "asreproast",
            "privilege_path": "service_account_to_domain_admin",
            "attack_complexity": "easy",
            "estimated_time": "45-60 minutes",
            "scenario_confidence": 0.95,
            "distinguishing_factors": [
                "service_accounts_without_preauth",
                "writedacl_permissions",
                "default_ad_configuration"
            ],
            "environmental_clues": [
                "domain_controller_role",
                "kerberos_authentication",
                "ldap_anonymous_access"
            ],
            "similar_scenarios": ["sauna_htb_easy", "active_htb_easy"],
            "unique_aspects": ["alfresco_service_account", "exchange_services"]
        }}

        Focus on characteristics that would help identify similar targets in the future.
        Use clear, practical language that a pentester would understand in the field.

        Filename: {filename}
        Text to analyze:
        {writeup_text[:8000]}
        """
        
        return self._claude_request(prompt, "scenario_fingerprint")
    
    def extract_success_patterns(self, writeup_text: str) -> Dict:
        """Extract why techniques succeeded - crucial for real-time recommendations"""
        
        prompt = f"""
        Analyze WHY techniques succeeded in this penetration test.
        Focus on the factors that made attacks work and how to recognize them.
        Make this practical for real-world pentesting.

        Return ONLY valid JSON:
        {{
            "success_factors": [
                {{
                    "technique": "ASREPRoast",
                    "success_reason": "Service account svc-alfresco had pre-authentication disabled",
                    "prerequisite_indicators": [
                        "kerberos_service_available",
                        "domain_controller_accessible",
                        "accounts_without_preauth_exist"
                    ],
                    "recognition_patterns": [
                        "service account naming (svc-*)",
                        "GetNPUsers returns hashes",
                        "no preauth required error"
                    ],
                    "failure_modes": [
                        "all_accounts_require_preauth",
                        "kerberos_not_accessible",
                        "no_service_accounts"
                    ],
                    "environmental_factors": [
                        "default_active_directory_config",
                        "legacy_service_configurations",
                        "insufficient_hardening"
                    ],
                    "success_probability": 0.87,
                    "typical_timeframe": "5-15 minutes"
                }}
            ],
            "critical_discoveries": [
                {{
                    "discovery": "svc-alfresco service account",
                    "discovery_method": "GetNPUsers.py enumeration",
                    "why_critical": "Led to domain admin via WriteDACL permission",
                    "how_to_recognize": [
                        "service account naming pattern",
                        "AS-REP roastable accounts",
                        "weak password patterns"
                    ],
                    "follow_up_actions": [
                        "crack_hash_with_hashcat",
                        "test_winrm_access",
                        "run_bloodhound_collection"
                    ]
                }}
            ],
            "escalation_keys": [
                {{
                    "privilege_level": "service_account",
                    "escalation_method": "WriteDACL_to_DCSync",
                    "why_possible": "Service account had WriteDACL permission on domain",
                    "recognition_signs": [
                        "bloodhound_shows_writedacl",
                        "service_account_in_privileged_groups",
                        "exchange_related_permissions"
                    ],
                    "exploitation_path": "Add-DomainObjectAcl → DCSync → Domain Admin"
                }}
            ]
        }}

        Text to analyze:
        {writeup_text[:10000]}
        """
        
        return self._claude_request(prompt, "success_patterns")
    
    def extract_decision_tree(self, writeup_text: str) -> Dict:
        """Extract decision logic - key for real-time suggestions"""
        
        prompt = f"""
        Extract the decision tree that led from initial reconnaissance to privilege escalation.
        Focus on decision points and branching logic that can be applied to new targets.
        Make this actionable for real-time pentesting decisions.

        Return ONLY valid JSON:
        {{
            "decision_points": [
                {{
                    "step": 1,
                    "situation": "Found ports 53,88,389,445 open on Windows host",
                    "decision": "Identify as Domain Controller and try Kerberos attacks first",
                    "reasoning": "Port combination indicates AD DC with high probability",
                    "confidence": 0.95,
                    "alternatives": [
                        {{"option": "smb_enumeration", "when": "if kerberos fails"}},
                        {{"option": "ldap_enumeration", "when": "if anonymous access"}}
                    ],
                    "success_indicators": [
                        "kerberos_service_responds",
                        "domain_name_discovered",
                        "ldap_base_dn_found"
                    ],
                    "next_decision": "choose_kerberos_attack_method"
                }},
                {{
                    "step": 2,
                    "situation": "Confirmed Active Directory environment",
                    "decision": "Try ASREPRoast before Kerberoasting",
                    "reasoning": "ASREPRoast doesn't require valid credentials",
                    "confidence": 0.85,
                    "prerequisites": ["domain_name_known", "kerberos_accessible"],
                    "success_indicators": ["accounts_without_preauth_found"],
                    "failure_fallbacks": ["kerberoasting", "password_spraying", "smb_enumeration"]
                }}
            ],
            "branching_logic": {{
                "if_asreproast_succeeds": {{
                    "action": "crack_hash_and_authenticate",
                    "tools": ["hashcat", "evil-winrm"],
                    "next_phase": "privilege_escalation_enumeration"
                }},
                "if_asreproast_fails": {{
                    "action": "try_alternative_attacks",
                    "alternatives": ["kerberoasting", "ldap_enumeration", "smb_shares"],
                    "decision_criteria": "based_on_anonymous_access_level"
                }},
                "if_credentials_obtained": {{
                    "action": "bloodhound_enumeration",
                    "purpose": "find_privilege_escalation_paths",
                    "tools": ["bloodhound-python", "sharphound"]
                }}
            }},
            "optimization_rules": [
                {{
                    "rule": "always_try_asreproast_first_on_ad",
                    "reasoning": "high_success_rate_and_no_credentials_needed",
                    "applicability": "active_directory_environments"
                }},
                {{
                    "rule": "run_bloodhound_after_any_domain_credentials",
                    "reasoning": "essential_for_privilege_escalation_paths",
                    "applicability": "domain_user_access_obtained"
                }}
            ]
        }}

        Text to analyze:
        {writeup_text[:12000]}
        """
        
        return self._claude_request(prompt, "decision_tree")
    
    def extract_applicability_rules(self, writeup_text: str) -> Dict:
        """Extract rules for when techniques apply to new targets"""
        
        prompt = f"""
        Extract precise applicability rules that determine when these techniques work on new targets.
        Focus on environmental indicators and prerequisites that a pentester can quickly identify.

        Return ONLY valid JSON:
        {{
            "technique_rules": [
                {{
                    "technique": "ASREPRoast",
                    "mitre_id": "T1558.004",
                    "required_services": ["kerberos"],
                    "required_ports": [88],
                    "os_requirements": ["windows"],
                    "environmental_prerequisites": [
                        "active_directory_domain",
                        "kerberos_authentication_enabled",
                        "accounts_without_preauth_exist"
                    ],
                    "success_indicators": [
                        "GetNPUsers_returns_hashes",
                        "domain_controller_accessible",
                        "service_accounts_present"
                    ],
                    "incompatible_with": [
                        "kerberos_disabled",
                        "all_accounts_require_preauth",
                        "network_isolation"
                    ],
                    "confidence_boosters": [
                        "service_account_naming_patterns",
                        "default_ad_configuration",
                        "legacy_exchange_services"
                    ],
                    "typical_success_rate": 0.87,
                    "estimated_time": "5-15 minutes"
                }}
            ],
            "environmental_detectors": {{
                "active_directory": {{
                    "port_indicators": [53, 88, 389, 445, 3268],
                    "service_indicators": ["kerberos", "ldap", "smb", "dns"],
                    "banner_indicators": ["Active Directory", "Windows Server"],
                    "confidence_threshold": 0.85
                }},
                "web_application": {{
                    "port_indicators": [80, 443, 8080, 8443],
                    "service_indicators": ["http", "https"],
                    "technology_indicators": ["apache", "nginx", "iis"],
                    "confidence_threshold": 0.90
                }}
            }},
            "attack_prioritization": {{
                "high_priority": [
                    {{
                        "attack": "asreproast",
                        "when": "active_directory_detected",
                        "reason": "high_success_rate_no_creds_needed"
                    }},
                    {{
                        "attack": "smb_anonymous_enumeration", 
                        "when": "smb_service_detected",
                        "reason": "often_reveals_usernames_and_shares"
                    }}
                ],
                "medium_priority": [
                    {{
                        "attack": "directory_bruteforce",
                        "when": "web_service_detected",
                        "reason": "reliable_but_time_consuming"
                    }}
                ]
            }}
        }}

        Text to analyze:
        {writeup_text[:8000]}
        """
        
        return self._claude_request(prompt, "applicability_rules")
    
    def extract_technique_intelligence(self, writeup_text: str) -> Dict:
        """Extract detailed technique intelligence for real-time suggestions"""
        
        prompt = f"""
        Extract detailed intelligence about specific techniques used in this writeup.
        Focus on command examples, tool effectiveness, and practical execution details.
        Make this immediately actionable for field use.

        Return ONLY valid JSON:
        {{
            "techniques": [
                {{
                    "name": "ASREPRoast",
                    "mitre_id": "T1558.004",
                    "category": "credential_access",
                    "phase": "initial_access",
                    "tools_used": [
                        {{
                            "name": "GetNPUsers.py",
                            "command_template": "GetNPUsers.py {{domain}}/ -dc-ip {{ip}} -no-pass",
                            "actual_command": "GetNPUsers.py htb.local/ -dc-ip 10.10.10.161 -no-pass",
                            "output_pattern": "$krb5asrep$23${{username}}@{{domain}}:",
                            "effectiveness_rating": 5,
                            "reliability": 0.95
                        }},
                        {{
                            "name": "hashcat",
                            "command_template": "hashcat -m 18200 {{hash_file}} {{wordlist}}",
                            "actual_command": "hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt",
                            "success_factors": ["weak_password", "common_wordlist_hit"],
                            "effectiveness_rating": 4
                        }}
                    ],
                    "prerequisites": [
                        "kerberos_service_accessible",
                        "domain_name_known",
                        "accounts_without_preauth"
                    ],
                    "success_indicators": [
                        "hash_extracted_successfully",
                        "hash_cracked_within_reasonable_time",
                        "credentials_provide_system_access"
                    ],
                    "common_failures": [
                        "no_vulnerable_accounts",
                        "strong_passwords_resist_cracking",
                        "network_connectivity_issues"
                    ],
                    "follow_up_techniques": [
                        "winrm_authentication",
                        "bloodhound_enumeration", 
                        "credential_spraying"
                    ],
                    "time_investment": "5-30 minutes",
                    "skill_level": "beginner"
                }}
            ],
            "tool_effectiveness": [
                {{
                    "tool": "BloodHound",
                    "use_case": "privilege_escalation_path_discovery",
                    "effectiveness_rating": 5,
                    "reliability": 0.98,
                    "learning_curve": "medium",
                    "essential_for": ["active_directory_environments"],
                    "alternatives": ["manual_ldap_enumeration", "powerview"],
                    "best_practices": [
                        "run_after_obtaining_domain_credentials",
                        "focus_on_shortest_path_to_domain_admin",
                        "validate_paths_before_exploitation"
                    ]
                }}
            ],
            "command_sequences": [
                {{
                    "sequence_name": "asreproast_to_domain_admin",
                    "steps": [
                        {{
                            "step": 1,
                            "command": "GetNPUsers.py htb.local/ -dc-ip 10.10.10.161 -no-pass",
                            "purpose": "Extract AS-REP hashes",
                            "expected_output": "Hash for svc-alfresco account"
                        }},
                        {{
                            "step": 2,
                            "command": "hashcat -m 18200 hash.txt rockyou.txt",
                            "purpose": "Crack extracted hash",
                            "expected_output": "Password: s3rvice"
                        }},
                        {{
                            "step": 3,
                            "command": "evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice",
                            "purpose": "Authenticate with cracked credentials",
                            "expected_output": "Remote shell as domain user"
                        }}
                    ],
                    "success_rate": 0.87,
                    "typical_duration": "15-45 minutes"
                }}
            ]
        }}

        Text to analyze:
        {writeup_text[:15000]}
        """
        
        return self._claude_request(prompt, "technique_intelligence")
    
    def extract_metadata_intelligence(self, writeup_text: str, filename: str) -> Dict:
        """Extract enhanced metadata optimized for intelligence matching"""
        
        prompt = f"""
        Extract metadata optimized for intelligence matching and scenario recognition.
        Focus on practical categorization that helps with real-time decision making.

        Return ONLY valid JSON:
        {{
            "basic_metadata": {{
                "name": "Forest",
                "difficulty": "Easy", 
                "os": "Windows Server 2019",
                "platform": "HackTheBox",
                "release_date": "2019-10-19",
                "author": "0xdf",
                "estimated_time": "45-60 minutes"
            }},
            "intelligence_metadata": {{
                "attack_complexity": "low",
                "skill_level_required": "beginner",
                "primary_attack_vectors": ["kerberos", "active_directory"],
                "key_vulnerabilities": ["asrep_roastable_accounts", "excessive_permissions"],
                "environment_type": "corporate_domain_controller",
                "real_world_relevance": "high",
                "learning_value": ["kerberos_attacks", "ad_privilege_escalation"],
                "prerequisite_knowledge": ["basic_ad_concepts", "kerberos_fundamentals"]
            }},
            "categorization": {{
                "primary_category": "active_directory",
                "subcategories": ["kerberos_attacks", "privilege_escalation"],
                "attack_types": ["credential_access", "privilege_escalation"],
                "defensive_lessons": ["disable_unused_accounts", "require_preauth", "audit_permissions"]
            }},
            "similarity_markers": {{
                "similar_boxes": ["Sauna", "Active", "Resolute"],
                "similarity_reasons": ["ad_environment", "kerberos_attacks", "service_accounts"],
                "unique_aspects": ["exchange_services", "writedacl_escalation"],
                "difficulty_factors": ["straightforward_attack_path", "well_documented_techniques"]
            }}
        }}

        Filename: {filename}
        Text: {writeup_text[:3000]}
        """
        
        return self._claude_request(prompt, "metadata_intelligence")
    
    def _claude_request(self, prompt: str, extraction_type: str) -> Dict:
        """Make Claude API request with enhanced retry logic and low-balance handling"""
        
        for attempt in range(self.config.max_retries):
            try:
                response = self.anthropic_client.messages.create(
                    model=self.config.model,
                    max_tokens=4096,
                    temperature=0.1,  # Low temperature for consistency
                    messages=[
                        {"role": "user", "content": prompt}
                    ]
                )
                
                content = response.content[0].text.strip()
                
                # Enhanced JSON parsing with better error handling
                try:
                    # Try direct parsing first
                    return json.loads(content)
                except json.JSONDecodeError:
                    # Try extracting JSON from markdown code blocks
                    json_patterns = [
                        r'```json\n(.*?)\n```',
                        r'```\n(.*?)\n```',
                        r'```json(.*?)```',
                        r'\{.*\}'  # Match any JSON object
                    ]
                    
                    for pattern in json_patterns:
                        json_match = re.search(pattern, content, re.DOTALL)
                        if json_match:
                            try:
                                json_content = json_match.group(1).strip() if json_match.groups() else json_match.group(0).strip()
                                return json.loads(json_content)
                            except json.JSONDecodeError:
                                continue
                    
                    # Try cleaning the content and parsing again
                    cleaned_content = self._clean_json_content(content)
                    try:
                        return json.loads(cleaned_content)
                    except json.JSONDecodeError:
                        print(f"⚠️ JSON parse failed for {extraction_type} (attempt {attempt + 1})")
                        print(f"Content preview: {content[:300]}...")
                        
                        if attempt == self.config.max_retries - 1:
                            return self._get_empty_response(extraction_type)
                        
            except Exception as e:
                error_msg = str(e).lower()
                
                # Check for common credit/billing errors
                if any(keyword in error_msg for keyword in ['credit', 'billing', 'payment', 'balance', 'insufficient', 'quota', 'limit']):
                    print(f"\n💳 BILLING ERROR DETECTED!")
                    print(f"❌ Error: {e}")
                    print(f"💰 Likely cause: Insufficient credits or billing issue")
                    print(f"🛑 STOPPING EXTRACTION to prevent further failures")
                    print(f"📊 Progress so far: {self.processed_count} writeups processed")
                    
                    # Save what we have so far
                    if hasattr(self, 'current_output_path'):
                        self._save_emergency_progress()
                    
                    # Give user options
                    print(f"\n🔧 Options:")
                    print(f"1. Add credits to your account and resume")
                    print(f"2. Review what's been processed so far")
                    print(f"3. Exit and resume later")
                    
                    user_choice = input("Choose (1/2/3): ").strip()
                    if user_choice == "1":
                        input("Press Enter after adding credits to continue...")
                        continue  # Retry the request
                    elif user_choice == "2":
                        self._show_progress_summary()
                        return self._get_empty_response(extraction_type)
                    else:
                        print("👋 Exiting gracefully. Your progress has been saved.")
                        exit(0)
                
                # Handle rate limiting
                elif any(keyword in error_msg for keyword in ['rate', 'limit', 'too many', 'requests']):
                    print(f"🚦 Rate limit hit. Waiting {self.config.delay_between_requests * 2} seconds...")
                    time.sleep(self.config.delay_between_requests * 2)
                    continue
                
                # Handle other API errors
                else:
                    print(f"❌ Claude request failed for {extraction_type} (attempt {attempt + 1}): {e}")
                    if attempt < self.config.max_retries - 1:
                        time.sleep(self.config.delay_between_requests * (attempt + 1))
                    else:
                        return self._get_empty_response(extraction_type)
        
        time.sleep(self.config.delay_between_requests)
        return self._get_empty_response(extraction_type)
    
    def _save_emergency_progress(self):
        """Save progress when extraction is interrupted"""
        try:
            emergency_file = self.current_output_path / "metadata" / "emergency_progress.json"
            progress_data = {
                "extraction_interrupted": datetime.now().isoformat(),
                "processed_count": self.processed_count,
                "failed_extractions": self.failed_extractions,
                "low_confidence_cases": self.low_confidence_cases,
                "extraction_stats": self.extraction_stats,
                "resume_instructions": "Run the script again - it will skip already processed files"
            }
            
            with open(emergency_file, 'w') as f:
                json.dump(progress_data, f, indent=2)
            
            print(f"💾 Emergency progress saved to {emergency_file}")
        except Exception as e:
            print(f"⚠️ Could not save emergency progress: {e}")
    
    def _show_progress_summary(self):
        """Show current progress summary"""
        print(f"\n📊 PROGRESS SUMMARY:")
        print(f"✅ Successfully processed: {self.processed_count}")
        print(f"❌ Failed: {len(self.failed_extractions)}")
        print(f"⚠️ Low confidence: {len(self.low_confidence_cases)}")
        print(f"📁 Files can be found in: intelligence_db/intelligence/")
        print(f"🔄 To resume: Run the script again (it skips completed files)")
        
        if self.failed_extractions:
            print(f"\n❌ Failed extractions: {self.failed_extractions}")
        if self.low_confidence_cases:
            print(f"\n⚠️ Low confidence cases: {self.low_confidence_cases}")
    
    def _clean_json_content(self, content: str) -> str:
        """Clean content to improve JSON parsing"""
        # Remove common non-JSON elements
        content = re.sub(r'^[^{]*', '', content)  # Remove text before first {
        content = re.sub(r'[^}]*$', '', content)  # Remove text after last }
        
        # Fix common JSON issues
        content = content.replace("'", '"')  # Single to double quotes
        content = re.sub(r',\s*}', '}', content)  # Trailing commas
        content = re.sub(r',\s*]', ']', content)  # Trailing commas in arrays
        
        return content
    
    def _get_empty_response(self, extraction_type: str) -> Dict:
        """Return appropriate empty response based on extraction type"""
        if extraction_type in ["scenario_fingerprint", "metadata_intelligence"]:
            return {}
        else:
            return {"error": f"Failed to extract {extraction_type}", "data": []}
    
    def validate_intelligence_quality(self, extracted_data: Dict, original_text: str) -> Tuple[float, Dict]:
        """Validate extraction quality for intelligence use cases"""
        
        quality_factors = {
            'scenario_uniqueness': 0.25,       # Can we distinguish this scenario?
            'success_logic_clarity': 0.25,     # Do we understand why it worked?
            'applicability_completeness': 0.20, # Can we apply to new targets?
            'decision_tree_depth': 0.15,       # Do we have decision logic?
            'technique_actionability': 0.15    # Are techniques actionable?
        }
        
        scores = {}
        total_score = 0.0
        
        # Check scenario fingerprint quality
        fingerprint = extracted_data.get('scenario_fingerprint', {})
        if fingerprint and fingerprint.get('port_signature') and fingerprint.get('environment_type'):
            scores['scenario_uniqueness'] = 1.0
        else:
            scores['scenario_uniqueness'] = 0.0
        
        # Check success patterns clarity
        patterns = extracted_data.get('success_patterns', {})
        success_factors = patterns.get('success_factors', [])
        if success_factors and len(success_factors) > 0:
            scores['success_logic_clarity'] = min(len(success_factors) / 3.0, 1.0)
        else:
            scores['success_logic_clarity'] = 0.0
        
        # Check applicability rules
        rules = extracted_data.get('applicability_rules', {})
        technique_rules = rules.get('technique_rules', [])
        if technique_rules and len(technique_rules) > 0:
            scores['applicability_completeness'] = min(len(technique_rules) / 2.0, 1.0)
        else:
            scores['applicability_completeness'] = 0.0
        
        # Check decision tree depth
        decision_tree = extracted_data.get('decision_tree', {})
        decision_points = decision_tree.get('decision_points', [])
        if decision_points and len(decision_points) >= 2:
            scores['decision_tree_depth'] = 1.0
        elif decision_points and len(decision_points) == 1:
            scores['decision_tree_depth'] = 0.5
        else:
            scores['decision_tree_depth'] = 0.0
        
        # Check technique actionability
        techniques = extracted_data.get('technique_intelligence', {})
        technique_list = techniques.get('techniques', [])
        if technique_list and any(t.get('tools_used') for t in technique_list):
            scores['technique_actionability'] = 1.0
        else:
            scores['technique_actionability'] = 0.0
        
        # Calculate weighted score
        for factor, weight in quality_factors.items():
            total_score += scores.get(factor, 0.0) * weight
        
        return total_score, scores
    
    def process_single_writeup(self, writeup_file: Path) -> Optional[Dict]:
        """Process a single writeup with complete intelligence extraction"""
        
        print(f"📄 Processing: {writeup_file.name}")
        
        try:
            # Read the markdown file
            with open(writeup_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract frontmatter and content
            if content.startswith('---'):
                parts = content.split('---', 2)
                if len(parts) >= 3:
                    frontmatter = parts[1]
                    writeup_text = parts[2]
                else:
                    writeup_text = content
            else:
                writeup_text = content
            
            # Multi-pass intelligence extraction
            print("  🧠 Extracting scenario fingerprint...")
            scenario_fingerprint = self.extract_scenario_fingerprint(writeup_text, writeup_file.name)
            self.extraction_stats['scenario_fingerprints'] += 1 if scenario_fingerprint else 0
            
            print("  🧠 Extracting success patterns...")
            success_patterns = self.extract_success_patterns(writeup_text)
            self.extraction_stats['success_patterns'] += 1 if success_patterns else 0
            
            print("  🧠 Extracting decision tree...")
            decision_tree = self.extract_decision_tree(writeup_text)
            self.extraction_stats['decision_trees'] += 1 if decision_tree else 0
            
            print("  🧠 Extracting applicability rules...")
            applicability_rules = self.extract_applicability_rules(writeup_text)
            self.extraction_stats['applicability_rules'] += 1 if applicability_rules else 0
            
            print("  🧠 Extracting technique intelligence...")
            technique_intelligence = self.extract_technique_intelligence(writeup_text)
            self.extraction_stats['technique_extractions'] += 1 if technique_intelligence else 0
            
            print("  🧠 Extracting enhanced metadata...")
            metadata = self.extract_metadata_intelligence(writeup_text, writeup_file.name)
            
            # Combine all intelligence
            intelligence_data = {
                "writeup_id": writeup_file.stem.replace(" ", "_"),  # Replace spaces with underscores
                "scenario_fingerprint": scenario_fingerprint,
                "success_patterns": success_patterns,
                "decision_tree": decision_tree,
                "applicability_rules": applicability_rules,
                "technique_intelligence": technique_intelligence,
                "metadata": metadata,
                "extraction_metadata": {
                    "parse_date": datetime.now().isoformat(),
                    "original_file": str(writeup_file),
                    "content_length": len(writeup_text),
                    "extraction_version": "2.0-claude",
                    "model_used": self.config.model
                }
            }
            
            # Validate intelligence quality
            confidence, quality_scores = self.validate_intelligence_quality(intelligence_data, writeup_text)
            intelligence_data["intelligence_confidence"] = confidence
            intelligence_data["quality_breakdown"] = quality_scores
            
            print(f"  ✓ Intelligence confidence: {confidence:.2f}")
            
            if confidence < self.config.confidence_threshold:
                self.low_confidence_cases.append(writeup_file.name)
                print(f"  ⚠️ Low intelligence quality - flagged for review")
            
            self.processed_count += 1
            self.extraction_stats['total_processed'] += 1
            
            return intelligence_data
            
        except Exception as e:
            print(f"  ❌ Failed: {e}")
            self.failed_extractions.append(writeup_file.name)
            return None
    
    def process_writeups_batch(self, writeups_dir: str, output_dir: str, max_files: int = None, batch_size: int = 50):
        """Process writeups with automatic batching, pauses, and credit management"""
        
        writeups_path = Path(writeups_dir)
        output_path = Path(output_dir)
        
        # Store output path for emergency saves
        self.current_output_path = output_path
        
        # Create output structure
        directories = [
            "writeups", "indexes", "aggregated", "metadata", 
            "intelligence", "scenarios", "techniques"
        ]
        for directory in directories:
            (output_path / directory).mkdir(parents=True, exist_ok=True)
        
        # Get markdown files and filter out already processed
        md_files = list(writeups_path.glob("*.md"))
        
        # Filter out already processed files
        unprocessed_files = []
        for file in md_files:
            output_file = output_path / "intelligence" / f"{file.stem.replace(' ', '_')}.json"
            old_output_file = output_path / "intelligence" / f"{file.stem}.json"
            if not (output_file.exists() or old_output_file.exists()):
                unprocessed_files.append(file)
        
        if max_files:
            unprocessed_files = unprocessed_files[:max_files]
        
        total_files = len(unprocessed_files)
        if total_files == 0:
            print("✅ All writeups already processed!")
            return
            
        print(f"🚀 Processing {total_files} writeups for intelligence extraction")
        print(f"📦 Batch size: {batch_size} writeups per batch")
        print(f"🤖 Model: {self.config.model}")
        print(f"⚡ Rate limit: 50 requests/minute (Claude Sonnet 4)")
        print(f"💰 Estimated cost: ${total_files * 0.30:.2f} - ${total_files * 0.45:.2f}")
        print(f"⏱️ Estimated time: {total_files * 1.2:.0f} - {total_files * 2.0:.0f} minutes ({total_files * 1.2/60:.1f} - {total_files * 2.0/60:.1f} hours)")
        print(f"🔄 Each writeup: ~6 API calls, ~1.2-2.0 minutes")
        print()
        
        # Calculate batches
        num_batches = (total_files + batch_size - 1) // batch_size
        print(f"📊 BATCH BREAKDOWN:")
        print(f"   Total batches: {num_batches}")
        print(f"   Batch size: {batch_size} writeups")
        print(f"   Cost per batch: ~${batch_size * 0.35:.2f}")
        print(f"   Time per batch: ~{batch_size * 1.5:.0f} minutes")
        print()
        print(f"💡 AUTOMATIC BATCHING FEATURES:")
        print(f"   • Processes {batch_size} writeups at a time")
        print(f"   • Pauses between batches for user confirmation")
        print(f"   • Handles credit exhaustion gracefully")
        print(f"   • Saves progress after each batch")
        print(f"   • Can resume from any point")
        print()
        
        if input("Continue with batched extraction? (y/n): ").lower() != 'y':
            return
        
        # Process in batches
        all_intelligence = {}
        overall_start_time = time.time()
        
        for batch_num in range(num_batches):
            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, total_files)
            batch_files = unprocessed_files[start_idx:end_idx]
            
            print(f"\n" + "="*60)
            print(f"🚀 BATCH {batch_num + 1}/{num_batches}")
            print(f"📁 Processing files {start_idx + 1}-{end_idx} of {total_files}")
            print(f"📊 Batch size: {len(batch_files)} writeups")
            print(f"💰 Estimated batch cost: ${len(batch_files) * 0.35:.2f}")
            print("="*60)
            
            batch_start_time = time.time()
            batch_success_count = 0
            batch_failures = []
            
            try:
                # Process each file in the current batch
                for i, writeup_file in enumerate(batch_files, 1):
                    global_index = start_idx + i
                    print(f"\n[{global_index}/{total_files}] [Batch {batch_num + 1}: {i}/{len(batch_files)}] Processing {writeup_file.name}")
                    
                    intelligence_data = self.process_single_writeup(writeup_file)
                    
                    if intelligence_data:
                        # Save individual intelligence file
                        output_file = output_path / "intelligence" / f"{writeup_file.stem.replace(' ', '_')}.json"
                        with open(output_file, 'w', encoding='utf-8') as f:
                            json.dump(intelligence_data, f, indent=2, ensure_ascii=False)
                        
                        all_intelligence[writeup_file.stem] = intelligence_data
                        batch_success_count += 1
                        print(f"  💾 Saved intelligence to {output_file}")
                    else:
                        batch_failures.append(writeup_file.name)
                    
                    # Mini progress report every 5 files within batch
                    if i % 5 == 0:
                        print(f"  📊 Batch progress: {i}/{len(batch_files)} ({i/len(batch_files)*100:.0f}%)")
                
                # Batch completion summary
                batch_elapsed = time.time() - batch_start_time
                print(f"\n✅ BATCH {batch_num + 1} COMPLETE!")
                print(f"   ✅ Successful: {batch_success_count}/{len(batch_files)}")
                print(f"   ❌ Failed: {len(batch_failures)}")
                print(f"   ⏱️ Batch time: {batch_elapsed/60:.1f} minutes")
                print(f"   💰 Actual cost: ~${batch_success_count * 0.35:.2f}")
                
                # Save intermediate summary after each batch
                self._save_intermediate_summary(output_path, all_intelligence, batch_num + 1, num_batches)
                
                # Check if this was the last batch
                if batch_num + 1 >= num_batches:
                    print(f"\n🎉 ALL BATCHES COMPLETE!")
                    break
                
                # Pause and ask user if they want to continue (with auto-continue timeout)
                print(f"\n⏸️ BATCH PAUSE - Ready for next batch")
                print(f"📊 Overall progress: {end_idx}/{total_files} writeups processed ({end_idx/total_files*100:.1f}%)")
                
                next_batch_size = min(batch_size, total_files - end_idx)
                next_batch_start = end_idx + 1
                next_batch_end = end_idx + next_batch_size
                
                print(f"⏭️ Next: Batch {batch_num + 2} of {num_batches} (writeups {next_batch_start}-{next_batch_end})")
                
                remaining_cost = (total_files - end_idx) * 0.17  # Using your actual cost rate
                print(f"💰 Remaining estimated cost: ${remaining_cost:.2f} (based on your $0.17/writeup rate)")
                print(f"⏱️ Remaining estimated time: {(total_files - end_idx) * 1.5:.0f} minutes")
                print()
                print("Options:")
                print("1) Continue to next batch")
                print("2) Stop here (progress saved)")
                print("3) Show detailed progress")
                print()
                print("⏰ Auto-continuing to next batch in 5 minutes if no input...")
                print("   (Press any key to make a choice)")
                print(f"⏭️ Next: Batch {batch_num + 2}/{num_batches} ({min(batch_size, total_files - end_idx)} writeups)")
                
                remaining_cost = (total_files - end_idx) * 0.17  # Using your actual cost rate
                print(f"💰 Remaining estimated cost: ${remaining_cost:.2f} (based on your $0.17/writeup rate)")
                print()
                print("Options:")
                print("1) Continue to next batch")
                print("2) Stop here (progress saved)")
                print("3) Show detailed progress")
                print()
                print("⏰ Auto-continuing to next batch in 5 minutes if no input...")
                print("   (Press any key to make a choice)")
                
                # Auto-continue timeout functionality
                import select
                import sys
                
                timeout_seconds = 300  # 5 minutes
                
                def get_user_input_with_timeout():
                    """Get user input with timeout for auto-continue"""
                    if sys.platform == "win32":
                        # Windows implementation
                        import msvcrt
                        start_time = time.time()
                        input_chars = ""
                        
                        while True:
                            if msvcrt.kbhit():
                                char = msvcrt.getch().decode('utf-8')
                                if char == '\r':  # Enter key
                                    print()
                                    return input_chars.strip()
                                elif char == '\b':  # Backspace
                                    if input_chars:
                                        input_chars = input_chars[:-1]
                                        print('\b \b', end='', flush=True)
                                else:
                                    input_chars += char
                                    print(char, end='', flush=True)
                            
                            elapsed = time.time() - start_time
                            if elapsed >= timeout_seconds:
                                print(f"\n⏰ Timeout reached - auto-continuing to next batch...")
                                return "1"  # Auto-continue
                            
                            time.sleep(0.1)
                    
                    else:
                        # Unix/Linux implementation
                        print("Enter choice: ", end='', flush=True)
                        ready, _, _ = select.select([sys.stdin], [], [], timeout_seconds)
                        
                        if ready:
                            return sys.stdin.readline().strip()
                        else:
                            print(f"\n⏰ Timeout reached - auto-continuing to next batch...")
                            return "1"  # Auto-continue
                
                try:
                    user_choice = get_user_input_with_timeout()
                except:
                    # Fallback if timeout doesn't work
                    print("Enter choice (1-3): ", end='', flush=True)
                    user_choice = input().strip()
                
                if user_choice == "2":
                    print(f"🛑 Stopping after batch {batch_num + 1}")
                    print(f"✅ Progress saved. You can resume later.")
                    break
                elif user_choice == "3":
                    self._show_detailed_progress(batch_num + 1, num_batches, end_idx, total_files)
                    print("\n⏰ Auto-continuing to next batch in 30 seconds...")
                    print("   (Press Ctrl+C to stop, or wait to continue)")
                    try:
                        time.sleep(30)
                    except KeyboardInterrupt:
                        print(f"\n🛑 Stopping after batch {batch_num + 1}")
                        print(f"✅ Progress saved. You can resume later.")
                        break
                
                print(f"\n🔄 Auto-starting batch {batch_num + 2}...")
                time.sleep(2)  # Brief pause before starting next batch
                
            except KeyboardInterrupt:
                print(f"\n⚠️ Batch interrupted by user (Ctrl+C)")
                print(f"✅ Progress through batch {batch_num + 1} has been saved")
                print(f"🔄 You can resume by running the script again")
                break
                
            except Exception as e:
                print(f"\n❌ Batch {batch_num + 1} failed with error: {e}")
                print(f"✅ Progress through previous batches has been saved")
                print(f"🔄 You can resume by running the script again")
                
                # Ask if user wants to continue or stop
                if input("Try to continue with next batch? (y/n): ").lower() != 'y':
                    break
        
        # Generate final intelligence summary
        self._generate_intelligence_summary(output_path, all_intelligence)
        
        overall_elapsed = time.time() - overall_start_time
        print(f"\n🎉 EXTRACTION SESSION COMPLETE!")
        print(f"✅ Successfully processed: {self.processed_count}")
        print(f"❌ Failed: {len(self.failed_extractions)}")
        print(f"⚠️ Low confidence: {len(self.low_confidence_cases)}")
        print(f"⏱️ Total session time: {overall_elapsed/60:.1f} minutes")
        print(f"📁 Results saved to: {output_path}")
        
        # Save comprehensive processing log
        self._save_processing_log(output_path, overall_elapsed)
    
    def _save_intermediate_summary(self, output_path: Path, all_intelligence: Dict, completed_batches: int, total_batches: int):
        """Save intermediate progress summary after each batch"""
        
        intermediate_summary = {
            "batch_progress": {
                "completed_batches": completed_batches,
                "total_batches": total_batches,
                "completion_percentage": (completed_batches / total_batches) * 100,
                "last_update": datetime.now().isoformat()
            },
            "extraction_stats": self.extraction_stats.copy(),
            "processed_count": self.processed_count,
            "failed_extractions": self.failed_extractions.copy(),
            "low_confidence_cases": self.low_confidence_cases.copy()
        }
        
        with open(output_path / "metadata" / "batch_progress.json", 'w') as f:
            json.dump(intermediate_summary, f, indent=2)
    
    def _show_detailed_progress(self, completed_batches: int, total_batches: int, files_processed: int, total_files: int):
        """Show detailed progress statistics"""
        
        print(f"\n📊 DETAILED PROGRESS REPORT")
        print(f"=" * 50)
        print(f"📦 Batches: {completed_batches}/{total_batches} ({completed_batches/total_batches*100:.1f}%)")
        print(f"📁 Files: {files_processed}/{total_files} ({files_processed/total_files*100:.1f}%)")
        print(f"✅ Successful extractions: {self.processed_count}")
        print(f"❌ Failed extractions: {len(self.failed_extractions)}")
        print(f"⚠️ Low confidence cases: {len(self.low_confidence_cases)}")
        
        if self.processed_count > 0:
            success_rate = (self.processed_count / files_processed) * 100
            print(f"📈 Success rate: {success_rate:.1f}%")
        
        estimated_remaining_cost = (total_files - files_processed) * 0.35
        print(f"💰 Estimated remaining cost: ${estimated_remaining_cost:.2f}")
        
        if self.failed_extractions:
            print(f"\n❌ Failed files: {', '.join(self.failed_extractions[-5:])}")
            if len(self.failed_extractions) > 5:
                print(f"   ... and {len(self.failed_extractions) - 5} more")
        
        if self.low_confidence_cases:
            print(f"\n⚠️ Low confidence files: {', '.join(self.low_confidence_cases[-5:])}")
            if len(self.low_confidence_cases) > 5:
                print(f"   ... and {len(self.low_confidence_cases) - 5} more")
    
    def _print_progress_report(self, current: int, total: int, start_time: float):
        """Print detailed progress statistics"""
        elapsed = time.time() - start_time
        rate = current / elapsed if elapsed > 0 else 0
        eta = (total - current) / rate if rate > 0 else 0
        
        print(f"\n📊 Progress Report [{current}/{total}]:")
        print(f"   Processed: {self.processed_count}")
        print(f"   Failed: {len(self.failed_extractions)}")
        print(f"   Success Rate: {(self.processed_count / current * 100):.1f}%")
        print(f"   Low Confidence: {len(self.low_confidence_cases)}")
        print(f"   Processing Rate: {rate:.1f} files/minute")
        print(f"   ETA: {eta/60:.1f} minutes")
        print(f"   Intelligence Stats:")
        for stat_name, count in self.extraction_stats.items():
            if stat_name != 'total_processed':
                print(f"     {stat_name}: {count}")
    
    def _generate_intelligence_summary(self, output_path: Path, all_intelligence: Dict):
        """Generate intelligence summary and statistics"""
        
        print("\n🧠 Generating intelligence summary...")
        
        summary = {
            "extraction_overview": {
                "total_writeups": len(all_intelligence),
                "extraction_date": datetime.now().isoformat(),
                "average_confidence": 0.0,
                "extraction_stats": self.extraction_stats,
                "model_used": self.config.model
            },
            "scenario_distribution": {},
            "technique_frequency": {},
            "environment_types": {},
            "attack_complexity_distribution": {},
            "high_confidence_extractions": [],
            "needs_review": self.low_confidence_cases
        }
        
        # Analyze extracted intelligence
        confidences = []
        scenario_types = {}
        techniques = {}
        environments = {}
        complexities = {}
        
        for writeup_id, intel in all_intelligence.items():
            # Confidence tracking
            confidence = intel.get('intelligence_confidence', 0.0)
            confidences.append(confidence)
            
            if confidence > 0.8:
                summary["high_confidence_extractions"].append({
                    "writeup_id": writeup_id,
                    "confidence": confidence,
                    "scenario": intel.get('scenario_fingerprint', {}).get('scenario_name', 'unknown')
                })
            
            # Scenario analysis
            scenario = intel.get('scenario_fingerprint', {})
            scenario_name = scenario.get('scenario_name', 'unknown')
            scenario_types[scenario_name] = scenario_types.get(scenario_name, 0) + 1
            
            # Environment analysis
            env_type = scenario.get('environment_type', 'unknown')
            environments[env_type] = environments.get(env_type, 0) + 1
            
            # Attack complexity
            complexity = scenario.get('attack_complexity', 'unknown')
            complexities[complexity] = complexities.get(complexity, 0) + 1
            
            # Technique frequency
            tech_intel = intel.get('technique_intelligence', {})
            for technique in tech_intel.get('techniques', []):
                tech_name = technique.get('name', 'unknown')
                techniques[tech_name] = techniques.get(tech_name, 0) + 1
        
        # Update summary with analysis
        summary["extraction_overview"]["average_confidence"] = sum(confidences) / len(confidences) if confidences else 0.0
        summary["scenario_distribution"] = dict(sorted(scenario_types.items(), key=lambda x: x[1], reverse=True))
        summary["technique_frequency"] = dict(sorted(techniques.items(), key=lambda x: x[1], reverse=True))
        summary["environment_types"] = dict(sorted(environments.items(), key=lambda x: x[1], reverse=True))
        summary["attack_complexity_distribution"] = complexities
        
        # Save intelligence summary
        with open(output_path / "metadata" / "intelligence_summary.json", 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"  📈 Most common scenarios: {list(summary['scenario_distribution'].keys())[:5]}")
        print(f"  🎯 Most frequent techniques: {list(summary['technique_frequency'].keys())[:5]}")
        print(f"  🌍 Environment distribution: {summary['environment_types']}")
    
    def _save_processing_log(self, output_path: Path, elapsed_time: float):
        """Save comprehensive processing log"""
        
        processing_log = {
            "processing_summary": {
                "total_processed": self.processed_count,
                "failed_extractions": self.failed_extractions,
                "low_confidence_cases": self.low_confidence_cases,
                "processing_time_minutes": elapsed_time / 60,
                "average_time_per_writeup": elapsed_time / max(self.processed_count, 1)
            },
            "extraction_statistics": self.extraction_stats,
            "configuration": {
                "model": self.config.model,
                "confidence_threshold": self.config.confidence_threshold,
                "max_retries": self.config.max_retries,
                "extraction_version": "2.0-claude"
            },
            "quality_analysis": {
                "high_confidence_count": len([case for case in self.low_confidence_cases if case not in self.low_confidence_cases]),
                "needs_review_count": len(self.low_confidence_cases),
                "success_rate": (self.processed_count / (self.processed_count + len(self.failed_extractions))) if (self.processed_count + len(self.failed_extractions)) > 0 else 0
            },
            "timestamp": datetime.now().isoformat()
        }
        
        with open(output_path / "metadata" / "processing_log.json", 'w') as f:
            json.dump(processing_log, f, indent=2)

def create_sample_intelligence_structure(output_dir: str):
    """Create sample intelligence database structure for reference"""
    
    output_path = Path(output_dir)
    
    # Sample scenario fingerprint
    sample_scenario = {
        "writeup_id": "forest_htb",
        "scenario_fingerprint": {
            "scenario_name": "windows_domain_controller_asreproast",
            "primary_services": ["kerberos", "ldap", "smb", "dns"],
            "port_signature": "53+88+389+445",
            "service_combination": "dns+kerberos+ldap+smb",
            "os_family": "windows_server",
            "environment_type": "active_directory",
            "entry_vector": "asreproast",
            "privilege_path": "service_account_to_domain_admin",
            "attack_complexity": "easy",
            "estimated_time": "45-60 minutes",
            "scenario_confidence": 0.95
        },
        "success_patterns": {
            "success_factors": [
                {
                    "technique": "ASREPRoast",
                    "success_reason": "Service account svc-alfresco had pre-authentication disabled",
                    "success_probability": 0.87,
                    "typical_timeframe": "5-15 minutes"
                }
            ]
        },
        "intelligence_confidence": 0.92
    }
    
    # Save sample
    sample_file = output_path / "intelligence" / "sample_forest.json"
    sample_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(sample_file, 'w') as f:
        json.dump(sample_scenario, f, indent=2)
    
    print(f"📋 Sample intelligence structure created at {sample_file}")

# Usage example and configuration
if __name__ == "__main__":
    # Configuration  
    config = IntelligenceConfig(
        anthropic_api_key="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",  # SET YOUR API KEY HERE
        model="claude-sonnet-4-20250514",  # Claude Sonnet 4
        confidence_threshold=0.7,
        max_retries=3,
        delay_between_requests=1.2  # Claude 4 has excellent rate limits
    )
    
    # Create extractor
    extractor = IntelligenceExtractor(config)
    
    print("🧠 Intelligence Extraction Engine v2.0 - Claude Sonnet 4 Edition")
    print("=============================================================")
    print()
    
    # Get available writeups
    writeups_path = Path("0xdf_writeups")
    if not writeups_path.exists():
        print("❌ Error: '0xdf_writeups' directory not found!")
        print("Please make sure the writeups directory exists.")
        exit(1)
    
    md_files = list(writeups_path.glob("*.md"))
    total_writeups = len(md_files)
    
    print(f"📁 Found {total_writeups} writeups in {writeups_path}")
    print(f"💰 Estimated cost per writeup: $0.30 - $0.45")
    print(f"⏱️ Estimated time per writeup: 1.2 - 2.0 minutes")
    print()
    
    # Simple options
    print("🎯 How many writeups would you like to process?")
    print(f"1) Process ALL {total_writeups} writeups (${total_writeups * 0.35:.2f} estimated)")
    print("2) Process a specific number")
    print("3) Test with just 5 writeups first")
    print("4) Exit")
    
    choice = input("Enter choice (1-4): ").strip()
    
    if choice == "1":
        max_files = None
        estimated_cost = total_writeups * 0.35
        estimated_time = total_writeups * 1.5 / 60  # hours
        
        print(f"\n📊 Processing ALL {total_writeups} writeups")
        print(f"💰 Estimated cost: ${estimated_cost:.2f}")
        print(f"⏱️ Estimated time: {estimated_time:.1f} hours")
        
        if estimated_cost > 100:
            print(f"⚠️ WARNING: Estimated cost exceeds $100!")
            
        confirm = input("Continue? (y/n): ").strip().lower()
        if confirm != 'y':
            print("👋 Operation cancelled")
            exit(0)
            
    elif choice == "2":
        try:
            max_files = int(input(f"Enter number of writeups to process (1-{total_writeups}): "))
            if max_files < 1 or max_files > total_writeups:
                print(f"❌ Invalid number. Must be between 1 and {total_writeups}")
                exit(1)
                
            estimated_cost = max_files * 0.35
            estimated_time = max_files * 1.5 / 60  # hours
            
            print(f"\n📊 Processing {max_files} writeups")
            print(f"💰 Estimated cost: ${estimated_cost:.2f}")
            print(f"⏱️ Estimated time: {estimated_time:.1f} hours")
            
            confirm = input("Continue? (y/n): ").strip().lower()
            if confirm != 'y':
                print("👋 Operation cancelled")
                exit(0)
                
        except ValueError:
            print("❌ Invalid input. Please enter a number.")
            exit(1)
            
    elif choice == "3":
        max_files = 5
        print(f"\n📊 Processing 5 writeups as a test")
        print(f"💰 Estimated cost: $1.75")
        print(f"⏱️ Estimated time: 7-10 minutes")
        
    elif choice == "4":
        print("👋 Goodbye!")
        exit(0)
        
    else:
        print("❌ Invalid choice")
        exit(1)
    
    # Final confirmation
    print(f"\n🚀 Ready to start intelligence extraction")
    print(f"🤖 Model: {config.model}")
    print(f"📁 Directory: {writeups_path}")
    print(f"📊 Writeups: {max_files if max_files else total_writeups}")
    print(f"💾 Output: intelligence_db/")
    
    final_confirm = input("\nStart extraction? (y/n): ").strip().lower()
    if final_confirm != 'y':
        print("👋 Operation cancelled")
        exit(0)
    
    # Process the writeups with automatic batching
    extractor.process_writeups_batch(
        writeups_dir="0xdf_writeups",
        output_dir="intelligence_db",
        max_files=max_files,
        batch_size=50  # Process 50 at a time with pauses
    )
    
    # Create sample structure for reference
    create_sample_intelligence_structure("intelligence_db")
    
    print(f"\n🎯 Next Steps:")
    print(f"1. Review intelligence_db/metadata/intelligence_summary.json")
    print(f"2. Check intelligence_db/intelligence/ for individual extractions")
    print(f"3. Review any low confidence cases if flagged")
    print(f"4. Build the real-time intelligence engine")
    print(f"5. Integrate with JASMIN for live assistance")
    print(f"\n💡 Intelligence Database Features:")
    print(f"• Scenario fingerprinting for target matching")
    print(f"• Success pattern analysis for technique selection")
    print(f"• Decision trees for real-time guidance") 
    print(f"• Applicability rules for environment matching")
    print(f"• Comprehensive technique intelligence")