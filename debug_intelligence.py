#!/usr/bin/env python3

"""
JASMIN Intelligence Debug Script
Test all imports and components individually
"""

import sys
import traceback
from pathlib import Path

def test_import(module_name, description):
    """Test importing a specific module"""
    print(f"🧪 Testing {description}...")
    try:
        if module_name == "numpy":
            import numpy
            print(f"✅ {description} - SUCCESS")
            return True
        elif module_name == "statistical_confidence_engine":
            from statistical_confidence_engine import IntegratedStatisticalEngine
            print(f"✅ {description} - SUCCESS")
            return True
        elif module_name == "intelligence_integration":
            from intelligence_integration import EnhancedIntelligenceIntegration
            print(f"✅ {description} - SUCCESS")
            return True
        elif module_name == "pattern_discovery_engine":
            from pattern_discovery_engine import EnhancedPatternDiscoveryEngine
            print(f"✅ {description} - SUCCESS")
            return True
        elif module_name == "intelligence_matcher":
            from intelligence_matcher import IntelligenceMatcher
            print(f"✅ {description} - SUCCESS")
            return True
    except ImportError as e:
        print(f"❌ {description} - IMPORT ERROR: {e}")
        return False
    except Exception as e:
        print(f"❌ {description} - ERROR: {e}")
        print(f"🔍 Traceback: {traceback.format_exc()}")
        return False

def test_statistical_engine():
    """Test the statistical engine initialization"""
    print(f"\n🧮 Testing Statistical Engine Initialization...")
    try:
        from statistical_confidence_engine import IntegratedStatisticalEngine
        engine = IntegratedStatisticalEngine()
        print(f"✅ Statistical engine created successfully")
        
        # Test a basic calculation
        test_ports = [80, 443]
        test_services = ['http', 'apache']
        results = engine.calculate_confidence(test_ports, test_services)
        
        if results:
            print(f"✅ Test calculation successful - {len(results)} results")
            for env_type, result in list(results.items())[:2]:
                print(f"   📊 {env_type}: {result.confidence:.1f}%")
        else:
            print(f"⚠️  Test calculation returned no results")
        
        return True
        
    except Exception as e:
        print(f"❌ Statistical engine test failed: {e}")
        print(f"🔍 Traceback: {traceback.format_exc()}")
        return False

def test_intelligence_integration():
    """Test the intelligence integration"""
    print(f"\n🧠 Testing Intelligence Integration...")
    try:
        from intelligence_integration import EnhancedIntelligenceIntegration
        integration = EnhancedIntelligenceIntegration()
        print(f"✅ Intelligence integration created successfully")
        print(f"   Initialized: {integration.initialized}")
        
        return True
        
    except Exception as e:
        print(f"❌ Intelligence integration test failed: {e}")
        print(f"🔍 Traceback: {traceback.format_exc()}")
        return False

def check_file_structure():
    """Check if all required files exist and are readable"""
    print(f"\n📁 Checking File Structure...")
    
    required_files = [
        'statistical_confidence_engine.py',
        'intelligence_integration.py', 
        'pattern_discovery_engine.py',
        'intelligence_matcher.py',
        'jasmin.py'
    ]
    
    all_present = True
    for filename in required_files:
        file_path = Path(filename)
        if file_path.exists():
            size = file_path.stat().st_size
            print(f"✅ {filename} - {size} bytes")
        else:
            print(f"❌ {filename} - NOT FOUND")
            all_present = False
    
    return all_present

def test_jarvis_integration():
    """Test the JASMIN integration import"""
    print(f"\n🎯 Testing JASMIN Integration Import...")
    try:
        # Test the import that JASMIN does
        from intelligence_integration import handle_intel_command, init_intelligence_system, auto_analyze_scan_results
        print(f"✅ JASMIN integration functions imported successfully")
        
        # Test initialization
        intel_system = init_intelligence_system()
        print(f"✅ Intelligence system initialization successful")
        print(f"   System ready: {intel_system.initialized if hasattr(intel_system, 'initialized') else 'Unknown'}")
        
        return True
        
    except Exception as e:
        print(f"❌ JASMIN integration test failed: {e}")
        print(f"🔍 Traceback: {traceback.format_exc()}")
        return False

def main():
    """Run all diagnostic tests"""
    print("🔍 JASMIN INTELLIGENCE DIAGNOSTIC")
    print("=" * 50)
    
    print(f"📍 Current directory: {Path.cwd()}")
    print(f"🐍 Python version: {sys.version}")
    print(f"📚 Python path: {sys.path[0]}")
    
    # Test file structure
    files_ok = check_file_structure()
    
    # Test individual imports
    print(f"\n🧪 IMPORT TESTS")
    print("-" * 30)
    numpy_ok = test_import("numpy", "NumPy library")
    pattern_ok = test_import("pattern_discovery_engine", "Pattern Discovery Engine")
    matcher_ok = test_import("intelligence_matcher", "Intelligence Matcher") 
    statistical_ok = test_import("statistical_confidence_engine", "Statistical Confidence Engine")
    integration_ok = test_import("intelligence_integration", "Intelligence Integration")
    
    # Test engine functionality
    if statistical_ok:
        engine_ok = test_statistical_engine()
    else:
        engine_ok = False
        
    if integration_ok:
        jasmin_ok = test_jarvis_integration()
    else:
        jasmin_ok = False
    
    # Summary
    print(f"\n📋 DIAGNOSTIC SUMMARY")
    print("=" * 30)
    
    all_tests = [
        ("File Structure", files_ok),
        ("NumPy", numpy_ok), 
        ("Pattern Engine", pattern_ok),
        ("Intelligence Matcher", matcher_ok),
        ("Statistical Engine Import", statistical_ok),
        ("Intelligence Integration Import", integration_ok),
        ("Statistical Engine Function", engine_ok),
        ("JASMIN Integration", jasmin_ok)
    ]
    
    passed = sum(1 for _, ok in all_tests if ok)
    total = len(all_tests)
    
    for test_name, result in all_tests:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {test_name}: {status}")
    
    print(f"\n🎯 OVERALL: {passed}/{total} tests passed")
    
    if passed == total:
        print(f"🎉 ALL TESTS PASSED! Intelligence system should work.")
        print(f"💡 If JASMIN still shows errors, the issue might be in the import order.")
    else:
        print(f"⚠️  {total - passed} tests failed. See errors above for details.")
        
        # Provide specific guidance
        if not numpy_ok:
            print(f"🔧 Fix: Install numpy with 'pip3 install numpy'")
        if not statistical_ok and numpy_ok:
            print(f"🔧 Fix: Check statistical_confidence_engine.py for syntax errors")
        if not integration_ok:
            print(f"🔧 Fix: Check intelligence_integration.py for syntax errors")

if __name__ == "__main__":
    main()