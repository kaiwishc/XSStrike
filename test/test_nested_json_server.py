#!/usr/bin/env python3
"""
Simple test server for nested JSON XSS testing
"""
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

@app.route('/nested_json_test', methods=['POST', 'GET'])
def nested_json_test():
    """Test endpoint that accepts nested JSON and reflects it back"""
    if request.method == 'POST':
        data = request.get_json()
        print(f"Received nested JSON data: {data}")
        
        # Generate HTML response that reflects the nested JSON values
        html = "<html><body>"
        html += "<h1>Nested JSON Test</h1>"
        html += "<div>Received data:</div>"
        
        # Recursively display nested values
        def render_nested(obj, prefix=''):
            result = ""
            if isinstance(obj, dict):
                for key, value in obj.items():
                    full_key = f"{prefix}.{key}" if prefix else key
                    if isinstance(value, dict):
                        result += render_nested(value, full_key)
                    else:
                        # Reflect the value directly (vulnerable to XSS)
                        result += f"<p>{full_key}: {value}</p>"
            return result
        
        html += render_nested(data)
        html += "</body></html>"
        
        response = make_response(html)
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        return response
    else:
        return '''
        <html>
        <body>
            <h1>Nested JSON XSS Test</h1>
            <p>POST nested JSON to this endpoint to test XSS</p>
            <p>Example: {"user": {"profile": {"name": "test"}}}</p>
        </body>
        </html>
        '''

@app.route('/nested_json_list_test', methods=['POST'])
def nested_json_list_test():
    """Test endpoint for nested JSON with arrays"""
    data = request.get_json()
    print(f"Received nested JSON with arrays: {data}")
    
    html = "<html><body>"
    html += "<h1>Nested JSON with Arrays Test</h1>"
    
    def render_with_arrays(obj, prefix=''):
        result = ""
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, dict):
                    result += render_with_arrays(value, full_key)
                elif isinstance(value, list):
                    for idx, item in enumerate(value):
                        array_key = f"{full_key}[{idx}]"
                        if isinstance(item, dict):
                            result += render_with_arrays(item, array_key)
                        else:
                            result += f"<p>{array_key}: {item}</p>"
                else:
                    result += f"<p>{full_key}: {value}</p>"
        return result
    
    html += render_with_arrays(data)
    html += "</body></html>"
    
    response = make_response(html)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response

if __name__ == '__main__':
    print("Starting nested JSON test server on http://localhost:5000")
    print("Test endpoints:")
    print("  - POST http://localhost:5000/nested_json_test")
    print("  - POST http://localhost:5000/nested_json_list_test")
    app.run(host='127.0.0.1', port=5000, debug=True)
