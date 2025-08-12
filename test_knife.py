#!/usr/bin/env python3

"""
Test Knife Target with Enhanced Statistical Confidence Engine
Ports: 22 (SSH), 80 (HTTP)
Services: ssh, http, apache
OS: Linux Ubuntu
"""

from statistical_confidence_engine import EnhancedStatisticalEngine

def debug_available_categories():
    """Debug what categories are actually available in the database"""
    
    print("🔍 DEBUGGING AVAILABLE CATEGORIES:")
    print("=" * 50)
    
    engine = EnhancedStatisticalEngine()
    
    # Check what categories exist in patterns
    all_categories = set()
    linux_categories = set()
    
    for pattern_id, pattern in engine.patterns.items():
        for env_type in pattern['environment_distribution'].keys():
            all_categories.add(env_type)
            if 'linux' in env_type.lower() or 'unix' in env_type.lower():
                linux_categories.add(env_type)
    
    print(f"📊 TOTAL CATEGORIES: {len(all_categories)}")
    for category in sorted(all_categories):
        print(f"   • {category}")
    
    print(f"\n🐧 LINUX-RELATED CATEGORIES: {len(linux_categories)}")
    for category in sorted(linux_categories):
        print(f"   • {category}")
    
    # Check what relevant categories are being filtered
    print(f"\n🎯 RELEVANT CATEGORIES (from engine filter):")
    for category in sorted(engine.relevant_categories):
        print(f"   • {category}")
    
    print(f"\n🚫 EXCLUDED CATEGORIES (from engine filter):")
    for category in sorted(engine.excluded_categories):
        print(f"   • {category}")

def test_knife_target():
    """Test the enhanced engine with Knife target"""
    
    print("\n🔪 KNIFE TARGET TEST (Ports 22+80, SSH+Apache, Linux):")
    print("=" * 60)
    
    # Knife target data from nmap scan
    knife_ports = [22, 80]
    knife_services = ['ssh', 'http', 'apache']
    knife_os = "Linux Ubuntu"
    
    print(f"Ports: {knife_ports}")
    print(f"Services: {knife_services}")
    print(f"OS: {knife_os}")
    print()
    
    # Initialize enhanced engine
    engine = EnhancedStatisticalEngine()
    
    # Calculate confidence
    results = engine.calculate_confidence(knife_ports, knife_services, knife_os)
    
    print("RESULTS:")
    print("-" * 30)
    
    # Sort by confidence
    sorted_results = sorted(results.items(), key=lambda x: x[1].confidence, reverse=True)
    
    for env_type, result in sorted_results:
        method_icon = "🎯" if result.detection_method == "deterministic" else "📊"
        
        # Show all results for debugging
        print(f"{method_icon} {env_type}: {result.confidence:.1f}% ({result.detection_method})")
        print(f"    Evidence: {result.evidence_count} patterns")
        print(f"    Success Rate: {result.success_probability:.1%}")
        print(f"    Uncertainty: ±{result.uncertainty:.1f}%")
        if result.supporting_patterns:
            print(f"    Top pattern: {result.supporting_patterns[0][:50]}...")
        print()
    
    # Analysis
    print("🔍 ANALYSIS:")
    print("-" * 30)
    
    # Check for any Linux-related results
    linux_results = {}
    for env_type, result in results.items():
        if 'linux' in env_type.lower() or 'unix' in env_type.lower():
            linux_results[env_type] = result.confidence
    
    if linux_results:
        print(f"🐧 Found Linux-related categories:")
        for category, confidence in linux_results.items():
            print(f"   • {category}: {confidence:.1f}%")
    else:
        print(f"❌ NO Linux-related categories found in results!")
        print(f"   This means 'linux_server' doesn't exist in the database")

if __name__ == "__main__":
    debug_available_categories()
    test_knife_target()