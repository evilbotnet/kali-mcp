#!/bin/bash

# Kali Tools MCP Server Setup Script
# For Apple Silicon Mac

echo "🔧 Setting up Kali Tools MCP Server..."

# Create project directory
mkdir -p kali-tools-mcp-server
cd kali-tools-mcp-server

echo "📁 Creating project files..."

# Build Docker image
echo "🐳 Building Docker image..."
docker build --platform linux/arm64 -t kali-tools-mcp-server .

# Test the image
echo "🧪 Testing Docker image..."
if docker run --rm --platform linux/arm64 kali-tools-mcp-server python -c "
import sys
sys.path.append('/app')
from server import KaliToolsServer
print('Server imports successfully!')
server = KaliToolsServer()
print(f'Loaded {len(server.tools_data)} Kali tools')
print(f'Categories: {list(server.categories.keys())}')
if server.tools_data:
    sample_tool = list(server.tools_data.keys())[0]
    print(f'Sample tool: {sample_tool}')
"; then
    echo "✅ Docker image built and tested successfully!"
else
    echo "❌ Docker image test failed"
    exit 1
fi

echo "🎉 Setup complete!"
echo ""
echo "Next steps:"
echo "1. Add the Claude Desktop configuration to your config file:"
echo "   ~/Library/Application Support/Claude/claude_desktop_config.json"
echo "2. Restart Claude Desktop"
echo ""
echo "The server will run on-demand when Claude Desktop needs it."
echo "No persistent container needed!"
echo ""
echo "Example queries to try:"
echo "- 'What Kali tools are available for SQL injection?'"
echo "- 'Show me password cracking tools in Kali'"
echo "- 'Get usage examples for sqlmap'"
echo "- 'List all tools in the forensics category'"