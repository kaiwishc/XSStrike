"""
Stored XSS Verifier Module

This module handles verification of stored XSS payloads by:
1. Injecting payloads into target URL (POST/PUT/etc)
2. Verifying payload execution on a separate verification URL
3. Supporting both standard HTTP and JS-rendered verification
4. Detecting XSS triggers on load, click, hover events
"""

import re
import time
from urllib.parse import unquote

import core.config
from core.log import setup_logger
from core.requester import requester
from core.config import xsschecker

logger = setup_logger(__name__)

# Import JS renderer (lazy import to avoid dependency issues)
_js_renderer = None


def get_js_renderer():
    """Lazy load JS renderer module"""
    global _js_renderer
    if _js_renderer is None:
        try:
            from core import js_renderer
            _js_renderer = js_renderer
        except ImportError as e:
            logger.warning(f'JS renderer not available: {e}')
            _js_renderer = False
    return _js_renderer if _js_renderer is not False else None


def detect_xss_in_content(html_content, payload):
    """
    Detect if XSS payload is present in HTML content
    
    Args:
        html_content: HTML content to check
        payload: The payload that was injected
        
    Returns:
        tuple: (found, context) where found is bool and context is string
    """
    if not html_content:
        return False, None
    
    html_lower = html_content.lower()
    payload_lower = payload.lower()
    
    # Remove markers for checking
    clean_payload = payload_lower.replace('st4r7s', '').replace('3nd', '')
    
    # Check if payload exists in HTML
    if clean_payload in html_lower:
        # Extract context around payload
        pos = html_lower.find(clean_payload)
        start = max(0, pos - 100)
        end = min(len(html_content), pos + len(clean_payload) + 100)
        context = html_content[start:end]
        return True, context
    
    return False, None


def detect_interactive_xss(html_content, payload):
    """
    Detect if XSS payload might be triggered by user interaction
    
    Looks for event handlers like onclick, onmouseover, onmouseenter, etc.
    
    Args:
        html_content: HTML content to check
        payload: The payload that was injected
        
    Returns:
        tuple: (found, event_type, context) where found is bool, 
               event_type is the detected event, context is string
    """
    if not html_content:
        return False, None, None
    
    html_lower = html_content.lower()
    payload_lower = payload.lower().replace('st4r7s', '').replace('3nd', '')
    
    # Common interactive event handlers
    interactive_events = [
        'onclick', 'ondblclick', 'onmousedown', 'onmouseup',
        'onmouseover', 'onmousemove', 'onmouseout', 'onmouseenter', 'onmouseleave',
        'onhover', 'onfocus', 'onblur', 'onchange', 'onsubmit',
        'onkeydown', 'onkeypress', 'onkeyup', 'ontouchstart', 'ontouchend'
    ]
    
    # Look for payload in event handler attributes
    for event in interactive_events:
        # Pattern: event="...payload..."
        pattern = rf'{event}\s*=\s*["\']([^"\']*{re.escape(payload_lower)}[^"\']*)["\']'
        match = re.search(pattern, html_lower, re.IGNORECASE)
        if match:
            # Extract larger context
            pos = match.start()
            start = max(0, pos - 150)
            end = min(len(html_content), pos + 200)
            context = html_content[start:end]
            return True, event, context
    
    return False, None, None


def verify_stored_xss_with_js(verify_url, headers, payload, timeout=10, wait_time=3):
    """
    Verify stored XSS using JS rendering (Playwright)
    
    This can detect XSS that triggers on page load or after JS execution
    
    Args:
        verify_url: URL to check for stored XSS
        headers: HTTP headers
        payload: The injected payload
        timeout: Request timeout
        wait_time: Time to wait for JS execution
        
    Returns:
        tuple: (success, method, context) where success is bool,
               method is detection method, context is evidence
    """
    js_renderer = get_js_renderer()
    if not js_renderer:
        logger.warning('JS renderer not available for stored XSS verification')
        return False, None, None
    
    try:
        logger.debug(f'Verifying stored XSS with JS rendering: {verify_url}')
        
        # Render the page with JavaScript
        html_content, status_code, final_url = js_renderer.render_page(
            verify_url,
            headers,
            wait_time
        )
        
        if not html_content:
            return False, None, None
        
        # Check if payload is present in rendered content
        found, context = detect_xss_in_content(html_content, payload)
        if found:
            logger.debug('Payload found in JS-rendered content')
            return True, 'js_rendered', context
        
        # Check for interactive XSS
        interactive, event_type, context = detect_interactive_xss(html_content, payload)
        if interactive:
            logger.debug(f'Interactive XSS detected: {event_type}')
            return True, f'interactive_{event_type}', context
        
        return False, None, None
        
    except Exception as e:
        logger.warning(f'Error in JS-based verification: {e}')
        return False, None, None


def verify_stored_xss_standard(verify_url, headers, method, payload, delay, timeout):
    """
    Verify stored XSS using standard HTTP request (no JS rendering)
    
    Args:
        verify_url: URL to check for stored XSS
        headers: HTTP headers
        method: HTTP method (GET, POST, etc)
        payload: The injected payload
        delay: Delay between requests
        timeout: Request timeout
        
    Returns:
        tuple: (success, method, context) where success is bool,
               method is detection method, context is evidence
    """
    try:
        logger.debug(f'Verifying stored XSS (standard): {verify_url}')
        
        # Make request to verification URL
        response = requester(verify_url, {}, headers, method, delay, timeout)
        
        if not response or not response.text:
            return False, None, None
        
        # Check if payload is present in response
        found, context = detect_xss_in_content(response.text, payload)
        if found:
            logger.debug('Payload found in response')
            return True, 'standard', context
        
        # Check for interactive XSS
        interactive, event_type, context = detect_interactive_xss(response.text, payload)
        if interactive:
            logger.debug(f'Interactive XSS detected: {event_type}')
            return True, f'interactive_{event_type}', context
        
        return False, None, None
        
    except Exception as e:
        logger.warning(f'Error in standard verification: {e}')
        return False, None, None


def verify_stored_xss(verify_url, headers, verify_method, payload, delay, timeout, use_js_render=False):
    """
    Main function to verify if a stored XSS payload was successfully injected
    
    Args:
        verify_url: URL to check for stored XSS
        headers: HTTP headers
        verify_method: HTTP method for verification
        payload: The injected payload
        delay: Delay between requests
        timeout: Request timeout
        use_js_render: Whether to use JS rendering
        
    Returns:
        tuple: (success, detection_method, context) where success is bool,
               detection_method describes how XSS was found, context is evidence
    """
    if not verify_url:
        return False, None, None
    
    # Try JS rendering if enabled
    if use_js_render:
        success, method, context = verify_stored_xss_with_js(
            verify_url, headers, payload, timeout, 
            wait_time=core.config.jsRenderWait
        )
        if success:
            return True, method, context
    
    # Fallback to or use standard HTTP verification
    success, method, context = verify_stored_xss_standard(
        verify_url, headers, verify_method, payload, delay, timeout
    )
    
    return success, method, context
