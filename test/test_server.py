#!/usr/bin/env python3
"""
Simple test server to demonstrate stored XSS detection functionality
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import json

# Simulate database storage
stored_comments = []

class TestHandler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        parsed = urlparse(self.path)
        
        if parsed.path == '/':
            self.send_html('''
                <html>
                <head><title>XSS Test Server</title></head>
                <body>
                    <h1>XSS Test Server</h1>
                    <h2>Submit Comment (POST)</h2>
                    <form action="/comment" method="POST">
                        <input name="name" placeholder="Name" /><br/>
                        <textarea name="comment" placeholder="Comment content"></textarea><br/>
                        <button type="submit">Submit</button>
                    </form>
                    <hr/>
                    <h2><a href="/view">View all comments</a></h2>
                </body>
                </html>
            ''')
        
        elif parsed.path == '/view':
            # Display stored comments (stored XSS verification point)
            comments_html = ""
            for comment in stored_comments:
                # Intentionally not escaped, simulating XSS vulnerability
                comments_html += f"""
                    <div class="comment">
                        <strong>{comment['name']}</strong>: {comment['comment']}
                    </div>
                """
            
            self.send_html(f'''
                <html>
                <head><title>Comments List</title></head>
                <body>
                    <h1>All Comments</h1>
                    <div id="comments">
                        {comments_html if comments_html else "<p>No comments yet</p>"}
                    </div>
                    <hr/>
                    <a href="/">Return to Home</a>
                </body>
                </html>
            ''')
        
        elif parsed.path.startswith('/view-interactive'):
            # Interactive XSS test page
            comments_html = ""
            for comment in stored_comments:
                # Create interactive elements
                comments_html += f"""
                    <div class="comment" onclick="{comment['comment']}" 
                         style="cursor:pointer; border:1px solid #ccc; padding:10px; margin:5px;">
                        Click to view comment from <strong>{comment['name']}</strong>
                    </div>
                """
            
            self.send_html(f'''
                <html>
                <head><title>Interactive Comments</title></head>
                <body>
                    <h1>Interactive Comments (Requires Click)</h1>
                    <div id="comments">
                        {comments_html if comments_html else "<p>No comments yet</p>"}
                    </div>
                    <hr/>
                    <a href="/">Return to Home</a>
                </body>
                </html>
            ''')
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        parsed = urlparse(self.path)
        
        if parsed.path == '/comment':
            # Read POST data
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = parse_qs(post_data)
            
            # Store comment
            comment = {
                'name': params.get('name', ['Anonymous'])[0],
                'comment': params.get('comment', [''])[0]
            }
            stored_comments.append(comment)
            
            # Return success response
            self.send_response(302)
            self.send_header('Location', '/view')
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    
    def send_html(self, content):
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))
    
    def log_message(self, format, *args):
        # Custom log format
        print(f"[{self.command}] {self.path} - {args[1]}")

if __name__ == '__main__':
    port = 8888
    server = HTTPServer(('localhost', port), TestHandler)
    print(f"""
Press Ctrl+C to stop the server
    """)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\nServer stopped")
        server.shutdown()
