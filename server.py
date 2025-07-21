#!/usr/bin/env python3
"""
Kali Tools MCP Server
A MCP server that provides access to Kali Linux Tools documentation from GitLab repository
"""

import json
import os
import re
import sys
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional
import asyncio
import logging

from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
from mcp.types import Resource, Tool, TextContent, ImageContent, EmbeddedResource
from pydantic import AnyUrl
import mcp.server.stdio

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class KaliToolsServer:
    def __init__(self):
        self.server = Server("kali-tools-server")
        self.tools_data = {}
        self.categories = {}
        self.kali_tools_path = Path("/app/kali-tools-data")
        self.load_tools_data()
        
    def load_tools_data(self):
        """Load Kali tools data from the cloned GitLab repository"""
        print("Loading Kali Tools data from GitLab repository...", file=sys.stderr)
        
        if not self.kali_tools_path.exists():
            print(f"ERROR: Kali tools directory not found: {self.kali_tools_path}", file=sys.stderr)
            logger.error(f"Kali tools directory not found: {self.kali_tools_path}")
            return
        
        # Debug: Show directory structure
        print(f"Repository path exists: {self.kali_tools_path}", file=sys.stderr)
        
        # List all files and directories in the repository
        all_items = list(self.kali_tools_path.iterdir())
        print(f"Items in repository root: {len(all_items)}", file=sys.stderr)
        for item in all_items[:10]:  # Show first 10 items
            print(f"  {item.name} ({'dir' if item.is_dir() else 'file'})", file=sys.stderr)
        
        # Look for markdown files recursively
        markdown_files = list(self.kali_tools_path.rglob("*.md"))
        print(f"Found {len(markdown_files)} total markdown files", file=sys.stderr)
        
        # Show some example paths
        for i, md_file in enumerate(markdown_files[:5]):
            print(f"  Example {i+1}: {md_file.relative_to(self.kali_tools_path)}", file=sys.stderr)
        
        # Look specifically for tool directories (common pattern in Kali tools)
        tool_dirs = []
        for item in self.kali_tools_path.iterdir():
            if item.is_dir() and not item.name.startswith('.'):
                # Check if this directory contains markdown files
                dir_md_files = list(item.rglob("*.md"))
                if dir_md_files:
                    tool_dirs.append((item, dir_md_files))
        
        print(f"Found {len(tool_dirs)} directories with markdown files", file=sys.stderr)
        
        for md_file in markdown_files:
            try:
                # Skip main index files that aren't actual tools
                if md_file.name.lower() in ['readme.md', '_index.md'] and md_file.parent == self.kali_tools_path:
                    print(f"Skipping main index file: {md_file.name}", file=sys.stderr)
                    continue
                
                # Skip other non-tool files
                if md_file.name.lower() in ['license.md', 'changelog.md', 'contributing.md']:
                    continue
                
                with open(md_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Show first few lines for debugging (limit to first 5 tools)
                if len(self.tools_data) < 5:
                    lines = content.split('\n')[:5]
                    print(f"File {md_file.relative_to(self.kali_tools_path)} first lines:", file=sys.stderr)
                    for line in lines:
                        print(f"  {line[:100]}", file=sys.stderr)
                
                # Extract tool name - try multiple strategies
                tool_name = self.extract_tool_name(md_file, content)
                
                if tool_name and tool_name not in ['kali tools', 'all kali tools']:  # Skip main index pages
                    parsed_data = self.parse_markdown_content(content)
                    
                    self.tools_data[tool_name] = {
                        'name': tool_name,
                        'description': parsed_data.get('description', ''),
                        'homepage': parsed_data.get('homepage', ''),
                        'repository': parsed_data.get('repository', ''),
                        'packages': parsed_data.get('packages', []),
                        'usage': parsed_data.get('usage', ''),
                        'installation': parsed_data.get('installation', ''),
                        'content': content,
                        'file_path': str(md_file),
                        'category': self.guess_category_from_content(content, tool_name)
                    }
                    
                    if len(self.tools_data) <= 5:  # Show first 5 successful parses
                        print(f"Successfully parsed tool: {tool_name} from {md_file.relative_to(self.kali_tools_path)}", file=sys.stderr)
                else:
                    if len(self.tools_data) < 10:  # Only show first few failures
                        print(f"Skipped or could not extract tool name from: {md_file.relative_to(self.kali_tools_path)} (extracted: '{tool_name}')", file=sys.stderr)
                    
            except Exception as e:
                logger.warning(f"Error loading {md_file}: {e}")
                print(f"Error loading {md_file}: {e}", file=sys.stderr)
        
        # Organize tools by categories
        self.organize_by_categories()
        
        logger.info(f"Loaded {len(self.tools_data)} Kali tools")
        print(f"Final result: Loaded {len(self.tools_data)} Kali tools", file=sys.stderr)
        
        # Debug: Show what we actually loaded
        if self.tools_data:
            print("Sample tools loaded:", file=sys.stderr)
            for i, (tool_name, data) in enumerate(list(self.tools_data.items())[:5]):
                print(f"  {tool_name}: {data.get('description', 'No description')[:50]}...", file=sys.stderr)
        else:
            print("WARNING: No tools were loaded successfully!", file=sys.stderr)

    def extract_tool_name(self, md_file: Path, content: str) -> str:
        """Extract tool name from file path or content"""
        # For debugging, show less verbose output after first few
        verbose = len(self.tools_data) < 5
        
        if verbose:
            print(f"Extracting tool name from: {md_file.relative_to(self.kali_tools_path)}", file=sys.stderr)
        
        # Strategy 1: Try to get from YAML frontmatter
        if content.startswith('---'):
            try:
                parts = content.split('---', 2)
                if len(parts) >= 3:
                    yaml_content = parts[1]
                    metadata = yaml.safe_load(yaml_content)
                    if metadata and 'title' in metadata:
                        tool_name = metadata['title'].lower().strip()
                        # Skip generic titles
                        if tool_name not in ['kali tools', 'all kali tools', 'tools', 'documentation']:
                            if verbose:
                                print(f"  Found in YAML frontmatter: {tool_name}", file=sys.stderr)
                            return tool_name
            except Exception as e:
                if verbose:
                    print(f"  YAML parsing error: {e}", file=sys.stderr)
        
        # Strategy 2: Use directory name (most reliable for this repo structure)
        if md_file.parent != self.kali_tools_path:
            dir_name = md_file.parent.name
            # Skip generic directory names
            if dir_name not in ['tools', 'documentation', 'kali-tools', 'all-tools']:
                # Clean up directory name but preserve hyphens and numbers
                clean_dir_name = re.sub(r'[^\w\-\+\.]', '', dir_name.lower())
                if clean_dir_name:
                    if verbose:
                        print(f"  Using directory name: {clean_dir_name}", file=sys.stderr)
                    return clean_dir_name
        
        # Strategy 3: Try to extract from first header
        lines = content.split('\n')
        for i, line in enumerate(lines[:15]):  # Check first 15 lines
            line = line.strip()
            if line.startswith('# '):
                tool_name = line[2:].strip()
                # Clean up the tool name but preserve important characters
                clean_name = re.sub(r'[^\w\-\+\.\s]', '', tool_name.lower())
                clean_name = re.sub(r'\s+', '-', clean_name.strip())  # Replace spaces with hyphens
                if clean_name and clean_name not in ['kali-tools', 'all-kali-tools', 'tools']:
                    if verbose:
                        print(f"  Found in header: {clean_name}", file=sys.stderr)
                    return clean_name
        
        # Strategy 4: Fall back to filename (but avoid index.md, README.md)
        if md_file.name.lower() not in ['index.md', 'readme.md', '_index.md']:
            tool_name = md_file.stem
            # Clean up filename-based tool name
            clean_name = re.sub(r'[^\w\-\+\.]', '', tool_name.lower())
            if clean_name and clean_name not in ['readme', 'index', 'license']:
                if verbose:
                    print(f"  Using filename: {clean_name}", file=sys.stderr)
                return clean_name
        
        if verbose:
            print(f"  Could not extract meaningful tool name", file=sys.stderr)
        return None

    def parse_markdown_content(self, content: str) -> Dict[str, Any]:
        """Parse markdown content to extract structured information"""
        data = {
            'description': '',
            'homepage': '',
            'repository': '',
            'packages': [],
            'usage': '',
            'installation': ''
        }
        
        lines = content.split('\n')
        
        # Parse YAML frontmatter if present
        yaml_data = {}
        if content.startswith('---'):
            try:
                parts = content.split('---', 2)
                if len(parts) >= 3:
                    yaml_content = parts[1]
                    yaml_data = yaml.safe_load(yaml_content) or {}
                    if yaml_data:
                        # Map common YAML fields
                        for key in ['homepage', 'repository', 'description']:
                            if key in yaml_data:
                                data[key] = str(yaml_data[key])
                        # Handle packages
                        if 'packages' in yaml_data:
                            if isinstance(yaml_data['packages'], list):
                                data['packages'] = yaml_data['packages']
                            else:
                                data['packages'] = [str(yaml_data['packages'])]
                    lines = parts[2].split('\n')
            except Exception as e:
                pass
        
        # Clean lines - remove Hugo shortcodes and comments
        clean_lines = []
        for line in lines:
            # Skip Hugo shortcodes
            if '{{% ' in line or ' %}}' in line:
                continue
            # Skip HTML comments
            if '<!--' in line or '-->' in line:
                continue
            # Skip empty lines
            if not line.strip():
                continue
            clean_lines.append(line)
        
        # Parse markdown content
        current_section = None
        usage_content = []
        install_content = []
        desc_content = []
        packages_info_content = []
        in_code_block = False
        found_first_header = False
        in_packages_info = False
        skip_next_lines = 0
        
        for i, line in enumerate(clean_lines):
            if skip_next_lines > 0:
                skip_next_lines -= 1
                continue
                
            line_stripped = line.strip()
            
            # Check for PackagesInfo section
            if 'packagesinfo:' in line_stripped.lower() or 'packages info:' in line_stripped.lower():
                in_packages_info = True
                current_section = 'packages info'
                continue
            
            # Track code blocks
            if line_stripped.startswith('```'):
                in_code_block = not in_code_block
                if current_section and any(keyword in current_section for keyword in ['usage', 'example', 'command']):
                    usage_content.append(line)
                continue
            
            # Track sections by headers
            if line_stripped.startswith('#'):
                current_section = line_stripped.lower()
                found_first_header = True
                in_packages_info = False  # End packages info section
                continue
            
            # Skip lines that are clearly not content
            if len(line_stripped) < 3:
                continue
            
            # Special handling for PackagesInfo content
            if in_packages_info or current_section == 'packages info':
                # This is likely the main description content
                if (not line_stripped.startswith('#') and 
                    not line_stripped.startswith('```') and
                    len(line_stripped) > 10):
                    packages_info_content.append(line_stripped)
                continue
            
            # Special handling for different content patterns
            if 'usage example' in line_stripped.lower() or 'example usage' in line_stripped.lower():
                # This line introduces usage examples
                current_section = 'usage example'
                continue
            
            # Collect content based on section or keywords
            if current_section:
                if any(keyword in current_section for keyword in ['usage', 'example', 'command', 'syntax', 'how to']):
                    usage_content.append(line)
                elif any(keyword in current_section for keyword in ['install', 'setup', 'apt', 'dependencies']):
                    install_content.append(line)
                elif any(keyword in current_section for keyword in ['description', 'about', 'overview', 'what', 'summary']):
                    if not line_stripped.startswith('#'):
                        desc_content.append(line_stripped)
                else:
                    # If we're in an unidentified section and haven't found description yet,
                    # treat reasonable content as potential description
                    if (not desc_content and not packages_info_content and
                        not any(skip in line_stripped.lower() for skip in ['usage example', 'attack the given', 'root@kali', '```']) and
                        len(line_stripped) > 30 and
                        not line_stripped.startswith('http')):
                        desc_content.append(line_stripped)
            elif found_first_header:
                # Content after first header but not in a specific section
                if not line_stripped.startswith('#') and len(line_stripped) > 10:
                    desc_content.append(line_stripped)
            elif not found_first_header:
                # Content before any headers - this is often the description
                if (not line_stripped.startswith('#') and 
                    len(line_stripped) > 20 and
                    not any(skip in line_stripped.lower() for skip in ['usage example', 'screenshot', 'video'])):
                    desc_content.append(line_stripped)
        
        # Build description - try multiple sources
        if not data['description']:
            # Debug: show what we're working with for first few tools
            debug_this = len(self.tools_data) < 3
            
            if debug_this:
                print(f"  DEBUG: Looking for description...", file=sys.stderr)
                print(f"  YAML data: {yaml_data.get('description', 'None')}", file=sys.stderr)
                print(f"  Desc content lines: {len(desc_content)}", file=sys.stderr)
                print(f"  Clean lines count: {len(clean_lines)}", file=sys.stderr)
                if clean_lines:
                    print(f"  First few clean lines:", file=sys.stderr)
                    for i, line in enumerate(clean_lines[:5]):
                        print(f"    {i}: {line[:80]}", file=sys.stderr)
            
            # Try YAML description first
            if 'description' in yaml_data and yaml_data['description']:
                data['description'] = str(yaml_data['description']).strip()
                if debug_this:
                    print(f"  Used YAML description: {data['description'][:50]}...", file=sys.stderr)
            # Try collected description content
            elif desc_content:
                # Take first few meaningful sentences
                description_text = ' '.join(desc_content[:3])  # First 3 lines
                # Clean up common markdown artifacts
                description_text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', description_text)  # Remove markdown links
                description_text = re.sub(r'[*_`]', '', description_text)  # Remove formatting
                description_text = re.sub(r'\s+', ' ', description_text)  # Normalize whitespace
                data['description'] = description_text.strip()[:400]  # Limit length
                if debug_this:
                    print(f"  Used desc content: {data['description'][:50]}...", file=sys.stderr)
            # Try first meaningful paragraph after cleaning
            elif clean_lines:
                for i, line in enumerate(clean_lines[:20]):  # Check first 20 clean lines
                    line = line.strip()
                    if (not line.startswith('#') and 
                        len(line) > 20 and 
                        not line.startswith('```') and
                        not line.startswith('{{') and  # Skip remaining Hugo syntax
                        not line.startswith('![') and  # Skip images
                        not any(skip in line.lower() for skip in ['screenshot', 'image', 'video', 'link', 'usage example', 'attack the given', 'root@kali'])):
                        # Clean up the line
                        clean_desc = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', line)
                        clean_desc = re.sub(r'[*_`]', '', clean_desc)
                        clean_desc = re.sub(r'\s+', ' ', clean_desc).strip()
                        if len(clean_desc) > 20:
                            data['description'] = clean_desc[:400]
                            if debug_this:
                                print(f"  Used line {i}: {data['description'][:50]}...", file=sys.stderr)
                            break
                
                if not data['description'] and debug_this:
                    print(f"  No suitable description line found", file=sys.stderr)
            
            # Final fallback: use title from YAML if available and meaningful
            if not data['description'] and 'title' in yaml_data:
                title = str(yaml_data['title']).strip()
                if title and title.lower() not in ['kali tools', 'all kali tools'] and len(title) > 2:
                    # Create a basic description from the title
                    data['description'] = f"{title} is a tool included in Kali Linux."
                    if debug_this:
                        print(f"  Used title fallback: {data['description']}", file=sys.stderr)
        
        # Build usage section
        if usage_content:
            data['usage'] = '\n'.join(usage_content).strip()
        
        # Build installation section
        if install_content:
            data['installation'] = '\n'.join(install_content).strip()
        
        # Extract URLs from entire content if not found in YAML
        if not data['homepage'] or not data['repository']:
            url_pattern = r'https?://[^\s\)\]\}\'"]+|www\.[^\s\)\]\}\']+'
            urls = re.findall(url_pattern, content)
            for url in urls:
                if ('github.com' in url or 'gitlab.com' in url) and '/tree/' not in url and '/blob/' not in url:
                    if not data['repository']:
                        data['repository'] = url.rstrip('/')
                elif not data['homepage'] and 'http' in url and not any(skip in url for skip in ['kali.org/tools', 'example.com']):
                    data['homepage'] = url.rstrip('/')
        
        # Extract package information if not found in YAML
        if not data['packages']:
            # Look for apt install commands
            apt_patterns = [
                r'(?:sudo\s+)?apt(?:-get)?\s+install\s+([^\n\r;]+)',
                r'Package:\s*([^\n\r]+)',
                r'install[:\s]+([a-zA-Z0-9\-\+\.]+)'
            ]
            
            for pattern in apt_patterns:
                packages = re.findall(pattern, content, re.IGNORECASE)
                if packages:
                    # Clean up package names
                    all_packages = []
                    for pkg_line in packages:
                        # Split by spaces and filter out flags
                        pkgs = [p.strip() for p in pkg_line.split() 
                               if p.strip() and not p.startswith('-') and len(p.strip()) > 1]
                        all_packages.extend(pkgs)
                    if all_packages:
                        data['packages'] = list(set(all_packages[:5]))  # Remove duplicates, limit to 5
                        break
        
        return data

    def guess_category_from_content(self, content: str, tool_name: str) -> str:
        """Guess tool category based on content and tool name"""
        content_lower = (content + ' ' + tool_name).lower()
        
        # Define category keywords
        categories = {
            'information-gathering': [
                'reconnaissance', 'recon', 'enumeration', 'scanning', 'discovery', 
                'fingerprint', 'dns', 'whois', 'subdomain', 'port scan', 'nmap',
                'directory', 'osint', 'google', 'shodan'
            ],
            'vulnerability-analysis': [
                'vulnerability', 'vuln', 'exploit', 'cve', 'security scanner',
                'audit', 'assessment', 'nikto', 'openvas', 'nessus'
            ],
            'web-applications': [
                'web', 'http', 'https', 'ssl', 'url', 'cookie', 'sql injection', 
                'xss', 'csrf', 'burp', 'proxy', 'spider', 'crawler', 'sqlmap'
            ],
            'database': [
                'sql', 'database', 'mysql', 'postgres', 'mongodb', 'oracle',
                'mssql', 'db', 'injection'
            ],
            'password-attacks': [
                'password', 'hash', 'crack', 'brute', 'dictionary', 'wordlist',
                'john', 'hashcat', 'hydra', 'medusa', 'rainbow'
            ],
            'wireless': [
                'wifi', 'wireless', 'bluetooth', 'wpa', 'wep', '802.11',
                'aircrack', 'kismet', 'reaver', 'wifite'
            ],
            'reverse-engineering': [
                'reverse', 'disassembly', 'debug', 'analysis', 'binary',
                'ida', 'ghidra', 'radare', 'objdump', 'strings'
            ],
            'exploitation': [
                'exploit', 'payload', 'shell', 'metasploit', 'backdoor',
                'framework', 'msfconsole', 'meterpreter'
            ],
            'forensics': [
                'forensic', 'recovery', 'carving', 'image', 'disk', 'memory',
                'volatility', 'autopsy', 'sleuth', 'foremost'
            ],
            'sniffing-spoofing': [
                'sniff', 'capture', 'packet', 'wireshark', 'tcpdump', 'mitm',
                'ettercap', 'dsniff', 'arpspoof'
            ],
            'post-exploitation': [
                'privilege', 'escalation', 'persistence', 'lateral', 'pivot',
                'post', 'empire', 'cobalt'
            ],
            'reporting': [
                'report', 'documentation', 'output', 'export', 'pdf',
                'template', 'generate'
            ]
        }
        
        for category, keywords in categories.items():
            if any(keyword in content_lower for keyword in keywords):
                return category
        
        return 'miscellaneous'

    def organize_by_categories(self):
        """Organize tools by categories"""
        for tool_name, tool_data in self.tools_data.items():
            category = tool_data.get('category', 'miscellaneous')
            if category not in self.categories:
                self.categories[category] = []
            self.categories[category].append(tool_name)

    def setup_handlers(self):
        """Set up MCP server handlers"""
        
        @self.server.list_resources()
        async def handle_list_resources() -> List[Resource]:
            """List available Kali tools resources"""
            resources = []
            for tool_name in self.tools_data.keys():
                resources.append(Resource(
                    uri=AnyUrl(f"kali-tools://{tool_name}"),
                    name=f"Kali Tool: {tool_name}",
                    description=f"Documentation for Kali Linux tool {tool_name}",
                    mimeType="text/plain"
                ))
            return resources

        @self.server.read_resource()
        async def handle_read_resource(uri: AnyUrl) -> str:
            """Read a specific Kali tool resource"""
            if not str(uri).startswith("kali-tools://"):
                raise ValueError(f"Unsupported URI scheme: {uri}")
                
            tool_name = str(uri).replace("kali-tools://", "")
            
            if tool_name not in self.tools_data:
                raise ValueError(f"Tool not found: {tool_name}")
                
            data = self.tools_data[tool_name]
            
            # Format the response
            result = f"# {tool_name}\n\n"
            
            if data.get('description'):
                result += f"## Description\n{data['description']}\n\n"
            
            if data.get('category'):
                result += f"**Category**: {data['category']}\n\n"
            
            if data.get('homepage'):
                result += f"**Homepage**: {data['homepage']}\n\n"
            
            if data.get('repository'):
                result += f"**Repository**: {data['repository']}\n\n"
            
            if data.get('packages'):
                result += f"**Packages**: {', '.join(data['packages'])}\n\n"
            
            if data.get('installation'):
                result += f"## Installation\n{data['installation']}\n\n"
            
            if data.get('usage'):
                result += f"## Usage Examples\n```bash\n{data['usage']}\n```\n\n"
            
            result += f"## Full Documentation\n{data['content']}\n"
            
            return result

        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available tools"""
            return [
                Tool(
                    name="search_kali_tools",
                    description="Search Kali Linux tools by name, description, or usage",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search query for tool name, description, or functionality"
                            },
                            "category": {
                                "type": "string",
                                "description": "Filter by tool category",
                                "enum": ["information-gathering", "vulnerability-analysis", "web-applications",
                                        "database", "password-attacks", "wireless", "reverse-engineering",
                                        "exploitation", "forensics", "sniffing-spoofing", "post-exploitation",
                                        "reporting", "miscellaneous"]
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="get_tool_details",
                    description="Get detailed information about a specific Kali tool",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "tool_name": {
                                "type": "string",
                                "description": "Name of the Kali tool"
                            }
                        },
                        "required": ["tool_name"]
                    }
                ),
                Tool(
                    name="list_tools_by_category",
                    description="List all tools in a specific category",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "category": {
                                "type": "string",
                                "description": "Tool category to list",
                                "enum": ["information-gathering", "vulnerability-analysis", "web-applications",
                                        "database", "password-attacks", "wireless", "reverse-engineering",
                                        "exploitation", "forensics", "sniffing-spoofing", "post-exploitation",
                                        "reporting", "miscellaneous"]
                            }
                        },
                        "required": ["category"]
                    }
                ),
                Tool(
                    name="get_tool_usage",
                    description="Get usage examples and command syntax for a specific tool",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "tool_name": {
                                "type": "string",
                                "description": "Name of the Kali tool"
                            }
                        },
                        "required": ["tool_name"]
                    }
                ),
                Tool(
                    name="list_categories",
                    description="List all available tool categories with counts",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                )
            ]

        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            """Handle tool calls"""
            
            if name == "search_kali_tools":
                query = arguments.get("query", "").lower()
                category_filter = arguments.get("category")
                
                results = []
                for tool_name, data in self.tools_data.items():
                    # Check category filter
                    if category_filter and data.get('category') != category_filter:
                        continue
                    
                    # Search in name, description, and usage
                    searchable_text = (
                        tool_name.lower() + " " +
                        data.get('description', '').lower() + " " +
                        data.get('usage', '').lower() + " " +
                        data.get('content', '').lower()
                    )
                    
                    if query in searchable_text:
                        results.append({
                            'name': tool_name,
                            'description': data.get('description', ''),
                            'category': data.get('category', 'miscellaneous')
                        })
                
                response = f"Found {len(results)} tools"
                if category_filter:
                    response += f" in category '{category_filter}'"
                response += f" matching '{query}':\n\n"
                
                for result in results[:20]:  # Limit to 20 results
                    response += f"**{result['name']}** ({result['category']})\n"
                    desc = result['description'][:200] if result['description'] else "No description available"
                    response += f"{desc}...\n\n"
                
                return [TextContent(type="text", text=response)]
            
            elif name == "get_tool_details":
                tool_name = arguments.get("tool_name", "")
                
                if tool_name not in self.tools_data:
                    return [TextContent(type="text", text=f"Tool '{tool_name}' not found in Kali tools database.")]
                
                data = self.tools_data[tool_name]
                response = f"# {tool_name}\n\n"
                
                if data.get('description'):
                    response += f"**Description**: {data['description']}\n\n"
                
                if data.get('category'):
                    response += f"**Category**: {data['category']}\n\n"
                
                if data.get('homepage'):
                    response += f"**Homepage**: {data['homepage']}\n\n"
                
                if data.get('repository'):
                    response += f"**Repository**: {data['repository']}\n\n"
                
                if data.get('packages'):
                    response += f"**Packages**: {', '.join(data['packages'])}\n\n"
                
                if data.get('installation'):
                    response += f"**Installation**:\n{data['installation']}\n\n"
                
                if data.get('usage'):
                    response += f"**Usage Examples**:\n```bash\n{data['usage'][:1000]}\n```\n\n"
                
                return [TextContent(type="text", text=response)]
            
            elif name == "list_tools_by_category":
                category = arguments.get("category", "")
                
                if category not in self.categories:
                    return [TextContent(type="text", text=f"Category '{category}' not found.")]
                
                tools = self.categories[category]
                response = f"Tools in '{category}' category ({len(tools)} found):\n\n"
                
                for tool in sorted(tools):
                    desc = self.tools_data[tool].get('description', '')[:100]
                    desc = desc if desc else "No description available"
                    response += f"- **{tool}**: {desc}...\n"
                
                return [TextContent(type="text", text=response)]
            
            elif name == "get_tool_usage":
                tool_name = arguments.get("tool_name", "")
                
                if tool_name not in self.tools_data:
                    return [TextContent(type="text", text=f"Tool '{tool_name}' not found.")]
                
                data = self.tools_data[tool_name]
                response = f"# {tool_name} - Usage Examples\n\n"
                
                if data.get('usage'):
                    response += f"```bash\n{data['usage']}\n```\n\n"
                else:
                    response += "No usage examples available for this tool.\n\n"
                
                if data.get('installation'):
                    response += f"**Installation**: {data['installation']}\n"
                
                return [TextContent(type="text", text=response)]
            
            elif name == "list_categories":
                response = "Kali Linux Tool Categories:\n\n"
                
                for category, tools in sorted(self.categories.items()):
                    response += f"**{category}** ({len(tools)} tools)\n"
                
                response += f"\nTotal: {len(self.tools_data)} tools across {len(self.categories)} categories"
                
                return [TextContent(type="text", text=response)]
            
            else:
                raise ValueError(f"Unknown tool: {name}")

async def main():
    """Main function to run the MCP server"""
    try:
        print("Starting Kali Tools MCP Server...", file=sys.stderr)
        server_instance = KaliToolsServer()
        server_instance.setup_handlers()
        
        print("Server handlers set up, starting stdio server...", file=sys.stderr)
        
        # Run the server using stdio transport
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            print("STDIO server started, running MCP server...", file=sys.stderr)
            await server_instance.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="kali-tools-server",
                    server_version="1.0.0",
                    capabilities=server_instance.server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={}
                    )
                )
            )
    except Exception as e:
        print(f"Error in main: {e}", file=sys.stderr)
        logger.error(f"Error in main: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())