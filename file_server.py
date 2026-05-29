import http.server
import socketserver
import os

PORT = 8080

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"))

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), http.server.SimpleHTTPRequestHandler) as httpd:
        print(f"Frontend served at http://localhost:{PORT}")
        print("Open this URL in two browser windows to test E2EE chat")
        httpd.serve_forever()
