import sys
from blackice.mcp.server import BlackIceMCPServer

def main():
    server = BlackIceMCPServer()
    server.run_stdio()

if __name__ == "__main__":
    main()
