"""
JavaScript Renderer Module using Playwright
Supports offline usage with local Chrome executable
"""
import os
import sys
from core.log import setup_logger

logger = setup_logger(__name__)

# Global browser instance for reuse
_browser = None
_playwright = None
_context = None  # Reuse context for better performance
_page = None  # Reuse page for better performance


def get_browser():
    """
    Get or create a browser instance
    Returns the browser instance for making requests
    """
    global _browser, _playwright
    
    if _browser is not None:
        return _browser
    
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        logger.error('Playwright is not installed. Run: pip install playwright')
        logger.error('For offline usage, install browsers: playwright install chromium')
        return None
    
    try:
        _playwright = sync_playwright().start()
        
        # Try to find local Chrome/Chromium executable
        chrome_paths = get_chrome_paths()
        browser_args = {
            'headless': True,  # Will be overridden by config
            'args': [
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-web-security',
                '--disable-features=IsolateOrigins,site-per-process'
            ]
        }
        
        # Check if local Chrome executable exists in project
        local_chrome = find_local_chrome()
        if local_chrome:
            logger.info(f'Using local Chrome: {local_chrome}')
            browser_args['executable_path'] = local_chrome
            _browser = _playwright.chromium.launch(**browser_args)
        else:
            # Try system Chrome paths
            for chrome_path in chrome_paths:
                if os.path.exists(chrome_path):
                    logger.info(f'Using system Chrome: {chrome_path}')
                    browser_args['executable_path'] = chrome_path
                    _browser = _playwright.chromium.launch(**browser_args)
                    break
            
            # Fallback to default Playwright chromium
            if _browser is None:
                logger.info('Using Playwright default Chromium')
                _browser = _playwright.chromium.launch(**browser_args)
        
        logger.info('Browser instance created successfully')
        return _browser
        
    except Exception as e:
        logger.error(f'Failed to create browser instance: {str(e)}')
        if _playwright:
            _playwright.stop()
        return None


def find_local_chrome():
    """
    Find Chrome executable in project directory
    Checks: drivers/chrome, drivers/chromium, browsers/chrome, browsers/chromium
    """
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Possible locations for local Chrome in project
    possible_dirs = [
        os.path.join(project_root, 'drivers', 'chrome'),
        os.path.join(project_root, 'drivers', 'chromium'),
        os.path.join(project_root, 'browsers', 'chrome'),
        os.path.join(project_root, 'browsers', 'chromium'),
    ]
    
    # Possible executable names
    if sys.platform == 'win32':
        exe_names = ['chrome.exe', 'chromium.exe']
    elif sys.platform == 'darwin':
        exe_names = ['Google Chrome', 'Chromium']
        # macOS app bundle paths
        for d in possible_dirs[:]:
            possible_dirs.append(os.path.join(d, 'Google Chrome.app', 'Contents', 'MacOS'))
            possible_dirs.append(os.path.join(d, 'Chromium.app', 'Contents', 'MacOS'))
    else:
        exe_names = ['chrome', 'chromium', 'chromium-browser']
    
    for directory in possible_dirs:
        for exe_name in exe_names:
            exe_path = os.path.join(directory, exe_name)
            if os.path.exists(exe_path) and os.access(exe_path, os.X_OK):
                return exe_path
    
    return None


def get_chrome_paths():
    """
    Get common Chrome/Chromium installation paths by platform
    """
    if sys.platform == 'win32':
        return [
            r'C:\Program Files\Google\Chrome\Application\chrome.exe',
            r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
            os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe'),
        ]
    elif sys.platform == 'darwin':
        return [
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
            '/Applications/Chromium.app/Contents/MacOS/Chromium',
        ]
    else:  # Linux
        return [
            '/usr/bin/google-chrome',
            '/usr/bin/chromium',
            '/usr/bin/chromium-browser',
            '/snap/bin/chromium',
        ]


def render_page(url, headers=None, wait_time=3):
    """
    Render a page with JavaScript execution
    
    Args:
        url: URL to render
        headers: HTTP headers to send
        wait_time: Seconds to wait for JavaScript execution
    
    Returns:
        tuple: (rendered_html, status_code, final_url) or (None, None, None) on error
    """
    global _context, _page
    
    browser = get_browser()
    if browser is None:
        return None, None, None
    
    try:
        # Reuse context and page for better performance
        if _context is None or _page is None:
            # Create a new context with custom headers and SSL verification disabled
            context_options = {
                'ignore_https_errors': True  # Disable SSL verification (like verify=False in requests)
            }
            if headers:
                # Filter out headers that can't be set via context
                allowed_headers = {k: v for k, v in headers.items() 
                                 if k.lower() not in ['host', 'content-length', 'connection']}
                if allowed_headers:
                    context_options['extra_http_headers'] = allowed_headers
            
            _context = browser.new_context(**context_options)
            _page = _context.new_page()
            logger.debug('Created new browser context and page')
        
        # Set cookies if specified
        import core.config
        if core.config.cookie:
            # Parse cookie string and add to context
            from urllib.parse import urlparse
            url_parts = urlparse(url)
            domain = url_parts.netloc
            
            # Parse cookie string (format: "name1=value1; name2=value2")
            cookie_pairs = [c.strip() for c in core.config.cookie.split(';')]
            for cookie_pair in cookie_pairs:
                if '=' in cookie_pair:
                    name, value = cookie_pair.split('=', 1)
                    cookie_dict = {
                        'name': name.strip(),
                        'value': value.strip(),
                        'domain': domain,
                        'path': '/'
                    }
                    _context.add_cookies([cookie_dict])
                    logger.debug(f'Added cookie: {name.strip()}={value.strip()}')
        
        # Navigate to URL with optimized wait strategy
        logger.debug(f'Rendering URL: {url}')
        
        # Use 'domcontentloaded' instead of 'networkidle' for faster loading
        # This waits for DOM to be ready, not all network requests
        response = _page.goto(url, wait_until='domcontentloaded', timeout=15000)
        
        # Smart wait: wait for page to be fully loaded or until timeout
        # This is more efficient than fixed wait time
        if wait_time > 0:
            try:
                # Wait for network to be idle (all network connections done)
                # But with a maximum timeout of wait_time seconds
                _page.wait_for_load_state('networkidle', timeout=wait_time * 1000)
                logger.debug(f'Page fully loaded before timeout')
            except Exception:
                # Timeout reached, but that's okay - continue anyway
                logger.debug(f'Reached maximum wait time ({wait_time}s), continuing...')
        
        # Get rendered HTML
        html_content = _page.content()
        status_code = response.status if response else 200
        final_url = _page.url
        
        logger.debug(f'Page rendered successfully. Status: {status_code}')
        
        return html_content, status_code, final_url
        
    except Exception as e:
        logger.warning(f'Error rendering page: {str(e)}')
        # Reset context and page on error
        if _page:
            try:
                _page.close()
            except:
                pass
        if _context:
            try:
                _context.close()
            except:
                pass
        _page = None
        _context = None
        return None, None, None


def close_browser():
    """
    Close the browser instance and cleanup
    """
    global _browser, _playwright, _context, _page
    
    # Close page first
    if _page:
        try:
            _page.close()
            logger.debug('Page closed')
        except Exception as e:
            logger.warning(f'Error closing page: {str(e)}')
        _page = None
    
    # Close context
    if _context:
        try:
            _context.close()
            logger.debug('Context closed')
        except Exception as e:
            logger.warning(f'Error closing context: {str(e)}')
        _context = None
    
    # Close browser
    if _browser:
        try:
            _browser.close()
            logger.info('Browser closed')
        except Exception as e:
            logger.warning(f'Error closing browser: {str(e)}')
        _browser = None
    
    # Stop playwright
    if _playwright:
        try:
            _playwright.stop()
        except Exception as e:
            logger.warning(f'Error stopping playwright: {str(e)}')
        _playwright = None


# Cleanup on exit
import atexit
atexit.register(close_browser)
