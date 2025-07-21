# Kali Tools MCP Server

A Model Context Protocol (MCP) server that provides comprehensive access to Kali Linux Tools documentation through Claude Desktop. Search, explore, and get detailed information about the 600+ penetration testing and security tools included in Kali Linux.

> **What is Kali Linux?** Kali Linux is the world's most advanced penetration testing platform, containing hundreds of tools for security testing, digital forensics, and reverse engineering.

## ✨ Features

- 🔍 **Smart Search**: Find tools by name, functionality, or category across 600+ Kali tools
- 📋 **Category Organization**: Browse tools by security domain (web apps, forensics, wireless, etc.)
- 📖 **Detailed Documentation**: Get installation instructions, usage examples, and command syntax
- 🎯 **Usage Examples**: Real command-line examples with explanations
- 🐳 **Dockerized**: Clean deployment with web scraping for up-to-date information
- 🍎 **Apple Silicon Optimized**: Native ARM64 support for M1/M2/M3 Macs
- 🚀 **On-Demand**: Fresh data loaded for each session

## 🎯 Use Cases

- **Penetration Testing**: Quick reference for tools during security assessments
- **Security Research**: Discover the right tool for specific testing scenarios
- **OSCP/CEH Preparation**: Learn about tools used in ethical hacking certifications
- **Red Team Operations**: Find specialized tools for various attack vectors
- **Blue Team Defense**: Understand attacker tools to improve defenses
- **Educational**: Comprehensive learning resource for cybersecurity students
- **CTF Competitions**: Fast lookup of available tools and their capabilities

## 🛠 Available Tool Categories

- **Information Gathering**: DNS enumeration, port scanning, reconnaissance
- **Vulnerability Analysis**: Vulnerability scanners, exploit databases
- **Web Applications**: SQL injection, XSS testing, web crawlers
- **Database Assessment**: Database-specific security tools
- **Password Attacks**: Hash cracking, brute force, wordlist generation
- **Wireless Attacks**: WiFi security testing, Bluetooth analysis
- **Reverse Engineering**: Binary analysis, debugging, disassembly
- **Exploitation Tools**: Exploit frameworks, payload generators
- **Forensics**: Digital forensics, data recovery, memory analysis
- **Sniffing & Spoofing**: Network monitoring, packet capture, MITM
- **Post Exploitation**: Privilege escalation, persistence, lateral movement
- **Reporting Tools**: Documentation and report generation

## 🚀 Quick Start

### Prerequisites

- Docker installed and running
- Claude Desktop application
- Apple Silicon Mac (M1/M2/M3) or compatible system

### 1. Setup Project

```bash
# Create project directory
mkdir kali-tools-mcp-server
cd kali-tools-mcp-server

# Copy the following files to this directory:
# - Dockerfile
# - requirements.txt  
# - server.py
```

### 2. Build Docker Image

```bash
# Build the image for Apple Silicon (includes web scraping - takes 3-5 minutes)
docker build --platform linux/arm64 -t kali-tools-mcp-server .

# Test the build
docker run --rm --platform linux/arm64 kali-tools-mcp-server python -c "
import sys; sys.path.append('/app')
from server import KaliToolsServer
server = KaliToolsServer()
# Kali Tools MCP Server

A Model Context Protocol (MCP) server that provides comprehensive access to Kali Linux Tools documentation through Claude Desktop. Search, explore, and get detailed information about 600+ penetration testing and security tools directly from your Claude conversations.

> **What is Kali Linux?** Kali Linux is the world's most advanced penetration testing platform, containing hundreds of tools for security testing, digital forensics, and reverse engineering. This MCP server brings that knowledge directly into Claude Desktop.

## ✨ Features

- 🔍 **Smart Search**: Find tools by name, functionality, or category across 600+ Kali tools
- 📋 **Category Organization**: Browse tools by security domain (web apps, forensics, wireless, etc.)
- 📖 **Detailed Documentation**: Get installation instructions, usage examples, and command syntax
- 🎯 **Usage Examples**: Real command-line examples with explanations
- 🐳 **Dockerized**: Clean deployment with GitLab repository integration
- 🍎 **Apple Silicon Optimized**: Native ARM64 support for M1/M2/M3 Macs
- 🚀 **On-Demand**: Fresh data loaded for each session
- 📊 **PackagesInfo Parsing**: Extracts actual tool descriptions from Kali documentation

## 🎯 Use Cases

- **Penetration Testing**: Quick reference for tools during security assessments
- **Security Research**: Discover the right tool for specific testing scenarios
- **OSCP/CEH Preparation**: Learn about tools used in ethical hacking certifications
- **Red Team Operations**: Find specialized tools for various attack vectors
- **Blue Team Defense**: Understand attacker tools to improve defenses
- **Educational**: Comprehensive learning resource for cybersecurity students
- **CTF Competitions**: Fast lookup of available tools and their capabilities

## 🛠 Available Tool Categories

- **Information Gathering**: DNS enumeration, port scanning, reconnaissance (nmap, dnsrecon, recon-ng)
- **Vulnerability Analysis**: Vulnerability scanners, exploit databases (nikto, openvas, searchsploit)
- **Web Applications**: SQL injection, XSS testing, web crawlers (sqlmap, burpsuite, dirb)
- **Database Assessment**: Database-specific security tools (sqlmap, dbpwaudit)
- **Password Attacks**: Hash cracking, brute force, wordlist generation (hashcat, john, hydra)
- **Wireless Attacks**: WiFi security testing, Bluetooth analysis (aircrack-ng, wifite, kismet)
- **Reverse Engineering**: Binary analysis, debugging, disassembly (radare2, ghidra, binwalk)
- **Exploitation Tools**: Exploit frameworks, payload generators (metasploit, searchsploit)
- **Forensics**: Digital forensics, data recovery, memory analysis (autopsy, volatility, sleuthkit)
- **Sniffing & Spoofing**: Network monitoring, packet capture, MITM (wireshark, ettercap, tcpdump)
- **Post Exploitation**: Privilege escalation, persistence, lateral movement (empire, powersploit)
- **Reporting Tools**: Documentation and report generation (dradis, faraday)

## 🚀 Quick Start

### Prerequisites

- Docker installed and running
- Claude Desktop application
- Apple Silicon Mac (M1/M2/M3) or compatible system

### 1. Setup Project

```bash
# Create project directory
mkdir kali-tools-mcp-server
cd kali-tools-mcp-server

# Copy the following files to this directory:
# - Dockerfile
# - requirements.txt  
# - server.py
```

### 2. Build Docker Image

```bash
# Build the image for Apple Silicon
docker build --platform linux/arm64 -t kali-tools-mcp-server .

# Test the build
docker run --rm --platform linux/arm64 kali-tools-mcp-server python -c "
import sys; sys.path.append('/app')
from server import KaliToolsServer
server = KaliToolsServer()
print(f'✅ Successfully loaded {len(server.tools_data)} Kali tools')
print(f'Categories: {list(server.categories.keys())}')
"
```

### 3. Configure Claude Desktop

Edit your Claude Desktop configuration file:

**Location**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "kali-tools": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "--platform",
        "linux/arm64",
        "kali-tools-mcp-server",
        "python",
        "/app/server.py"
      ],
      "env": {}
    }
  }
}
```

### 4. Restart Claude Desktop

Completely quit and restart Claude Desktop to load the new MCP server.

## 💬 Usage Examples

Once configured, you can interact with the Kali Tools database directly through Claude Desktop:

### Search for Tools
```
"What Kali tools are available for SQL injection testing?"
"Search for password cracking tools"
"Show me wireless security tools"
"Find forensics tools for memory analysis"
```

### Get Tool Details
```
"Get detailed information about sqlmap"
"Show me usage examples for hashcat"
"How do I install and use wireshark in Kali?"
"What are the command-line options for nmap?"
```

### Browse by Category
```
"List all web application testing tools"
"Show me tools in the exploitation category"
"What forensics tools are available?"
"List all vulnerability analysis tools"
```

### Usage and Examples
```
"Show me sqlmap usage examples"
"How do I use burpsuite for web testing?"
"Give me nmap command examples"
"What are common metasploit commands?"
```

## 🛠 Available Tools

The MCP server provides five main tools:

### 1. `search_kali_tools`
Search the Kali tools database by name, description, or functionality.

**Parameters:**
- `query` (required): Search term
- `category` (optional): Filter by tool category

**Example**: Search for "sql injection" tools in "web-applications" category

### 2. `get_tool_details`
Get comprehensive information about a specific tool.

**Parameters:**
- `tool_name` (required): Name of the Kali tool

**Example**: Get complete documentation for "sqlmap"

### 3. `list_tools_by_category`
List all tools in a specific security category.

**Parameters:**
- `category` (required): Tool category (web-applications, forensics, etc.)

**Example**: List all password attack tools

### 4. `get_tool_usage`
Get usage examples and command syntax for a specific tool.

**Parameters:**
- `tool_name` (required): Name of the tool

**Example**: Get usage examples for "nmap"

### 5. `list_categories`
Show all available tool categories with tool counts.

**Example**: See overview of all tool categories

## 📁 Project Structure

```
kali-tools-mcp-server/
├── Dockerfile              # Container with Kali tools GitLab repository
├── requirements.txt        # Python dependencies (MCP, PyYAML)
├── server.py              # Main MCP server with PackagesInfo parsing
├── build.sh              # Automated setup script
└── README.md             # This documentation
```

## 🔧 Architecture

The MCP server works by:

1. **Repository Cloning**: Clones official Kali tools documentation from GitLab during build
2. **PackagesInfo Parsing**: Extracts tool descriptions from PackagesInfo sections in markdown files
3. **Smart Categorization**: Automatically categorizes tools by functionality using keyword analysis
4. **Content Extraction**: Parses YAML frontmatter, usage examples, and installation instructions
5. **MCP Interface**: Provides search and query capabilities through MCP tools
6. **On-Demand Execution**: Runs fresh containers for each Claude Desktop session

## 📊 Data Sources

- **Primary**: Official Kali Linux tools documentation from GitLab repository
- **Structure**: Individual tool directories containing `index.md` files
- **Content**: PackagesInfo sections, YAML frontmatter, usage examples
- **Categories**: Intelligent categorization based on tool descriptions and functionality

## 🔍 Key Parsing Features

**PackagesInfo Detection:**
- Automatically finds and extracts content following "PackagesInfo:" sections
- This is where the actual tool descriptions are located in Kali documentation
- Prioritizes this content over other description sources

**YAML Frontmatter:**
- Extracts title, homepage, repository, and other metadata
- Handles package information and installation details

**Content Cleaning:**
- Filters out Hugo shortcodes and HTML comments
- Removes markdown formatting for clean descriptions
- Skips usage examples when looking for descriptions

## 🐛 Troubleshooting

### Common Issues

**Build takes longer than expected:**
- The build includes cloning the full Kali tools GitLab repository
- Expected build time: 2-3 minutes on good internet connection
- Subsequent builds use Docker layer caching for speed

**Limited tools loaded:**
- Check that GitLab repository was cloned successfully
- Verify Docker has sufficient disk space
- The server should load 600+ tools if working correctly

**Description parsing issues:**
- Most tools should have meaningful descriptions from PackagesInfo sections
- Some tools may fall back to YAML titles if PackagesInfo is missing
- Check debug output for parsing details

### Debug Commands

```bash
# Test Docker image and tool loading with debug output
docker run --rm --platform linux/arm64 kali-tools-mcp-server python -c "
import sys; sys.path.append('/app')
from server import KaliToolsServer
print('=== Kali Tools Server Debug ===')
server = KaliToolsServer()
print(f'Loaded: {len(server.tools_data)} tools')
print(f'Categories: {list(server.categories.keys())}')
print('Sample tools with descriptions:')
for i, (name, data) in enumerate(list(server.tools_data.items())[:5]):
    desc = data.get('description', 'No description')[:60]
    print(f'  {name}: {desc}...')
"

# Check configuration file syntax
cat ~/Library/Application\ Support/Claude/claude_desktop_config.json | python -m json.tool

# Test specific tool data
docker run --rm --platform linux/arm64 kali-tools-mcp-server python -c "
import sys; sys.path.append('/app')
from server import KaliToolsServer
server = KaliToolsServer()
if 'sqlmap' in server.tools_data:
    tool = server.tools_data['sqlmap']
    print('SQLMap data:')
    print(f'  Description: {tool.get(\"description\", \"None\")[:100]}')
    print(f'  Category: {tool.get(\"category\", \"None\")}')
    print(f'  Usage available: {bool(tool.get(\"usage\"))}')
else:
    print('sqlmap not found')
"
```

### Performance Notes

- **Container Startup**: ~10-15 seconds for fresh container with full tool parsing
- **Search Performance**: Fast in-memory search across all tools and descriptions
- **Memory Usage**: ~150-300MB per container instance
- **Data Processing**: PackagesInfo parsing improves description quality significantly

## 🔒 Security Considerations

**Important Security Notes:**

- This server provides **read-only access** to Kali tools documentation
- Kali tools are **legitimate security testing utilities** that could be misused
- **Use only in authorized testing environments**
- **Follow responsible disclosure** practices for any vulnerabilities found
- The Docker container has **no network access** except during build

**Best Practices:**
- Only use for authorized penetration testing and security research
- Understand your organization's security policies before deployment
- Keep the server updated with latest Kali tools documentation
- Use in controlled environments for educational purposes

## 🎓 Educational Value

This MCP server serves as:

- **Learning Resource**: Comprehensive catalog of security tools with real descriptions
- **Reference Guide**: Quick lookup during security assessments and learning
- **Training Aid**: Discover new tools and their capabilities
- **Certification Prep**: Study aid for OSCP, CEH, and other security certifications
- **Tool Discovery**: Find the right tool for specific security testing scenarios

## 📄 License & Attribution

This project is for educational and legitimate security research purposes.

- **Kali Tools Data**: Subject to Kali Linux documentation license
- **GitLab Repository**: https://gitlab.com/kalilinux/documentation/kali-tools
- **MCP Server Code**: Educational use with responsible security practices
- **Docker Configuration**: Freely usable for legitimate security research

## 🤝 Contributing

Improvements welcome! Areas for contribution:

- Enhanced PackagesInfo parsing for edge cases
- Additional data extraction from tool documentation
- Performance optimizations for large datasets
- Better error handling and retry logic
- Integration with other security tool databases
- Improved categorization algorithms

## 🚀 Future Enhancements

Planned features:
- Tool installation verification and dependency checking
- Integration with actual Kali Linux systems
- Tool dependency mapping and relationship analysis
- Usage statistics and tool recommendations
- Integration with CVE databases and vulnerability information
- Export functionality for tool lists and documentation

## 📚 Learn More

- **Kali Linux**: [https://www.kali.org](https://www.kali.org)
- **Kali Tools**: [https://www.kali.org/tools/](https://www.kali.org/tools/)
- **Kali Documentation**: [https://www.kali.org/docs/](https://www.kali.org/docs/)
- **GitLab Repository**: [https://gitlab.com/kalilinux/documentation/kali-tools](https://gitlab.com/kalilinux/documentation/kali-tools)
- **Model Context Protocol**: [https://modelcontextprotocol.io](https://modelcontextprotocol.io)
- **Penetration Testing**: [https://www.kali.org/docs/introduction/](https://www.kali.org/docs/introduction/)

---

**⚡ Ready to explore? Ask Claude: "What are the best Kali tools for web application testing?"**
