import random
import requests
import time
from urllib3.exceptions import ProtocolError
import warnings

import core.config
from core.utils import converter, getVar, unflattenJSON
from core.log import setup_logger

logger = setup_logger(__name__)

warnings.filterwarnings('ignore')  # Disable SSL related warnings

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


def requester(url, data, headers, method, delay, timeout):
    if method is True:
        method = 'GET'
    elif method is False:
        method = 'POST'
    if getVar('jsonData'):
        # Unflatten the data back to nested JSON structure
        data = unflattenJSON(data)
        data = converter(data)
    elif getVar('path'):
        url = converter(data, url)
        data = []
        method = 'GET'
    time.sleep(delay)
    user_agents = ['Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991']
    if 'User-Agent' not in headers:
        headers['User-Agent'] = random.choice(user_agents)
    elif headers['User-Agent'] == '$':
        headers['User-Agent'] = random.choice(user_agents)
    logger.debug('Requester url: {}'.format(url))
    logger.debug('Requester method: {}'.format(method))
    logger.debug_json('Requester data:', data)
    logger.debug_json('Requester headers:', headers)
    
    # Check if JS rendering is enabled
    if core.config.jsRender and method == 'GET':
        js_renderer = get_js_renderer()
        if js_renderer:
            logger.debug('Using JS renderer for request')
            try:
                # Render page with JavaScript
                html_content, status_code, final_url = js_renderer.render_page(
                    url if not data else url + '?' + '&'.join([f'{k}={v}' for k, v in data.items()]),
                    headers,
                    core.config.jsRenderWait
                )
                
                if html_content:
                    # Create a mock response object
                    response = requests.Response()
                    response._content = html_content.encode('utf-8')
                    response.status_code = status_code or 200
                    response.url = final_url or url
                    response.headers['Content-Type'] = 'text/html; charset=utf-8'
                    logger.debug('JS rendering successful')
                    return response
                else:
                    logger.warning('JS rendering failed, falling back to standard request')
            except Exception as e:
                logger.warning(f'JS rendering error: {e}, falling back to standard request')
        else:
            logger.warning('JS renderer not available, using standard request')
    
    # Standard request (fallback or when JS rendering is disabled)
    try:
        if method == 'GET':
            response = requests.get(url, params=data, headers=headers,
                                    timeout=timeout, verify=False, proxies=core.config.proxies)
        elif getVar('jsonData'):
            # For JSON data, it's already been processed (unflattened and converted)
            # data is now a JSON string, we need to parse it for requests.request json parameter
            import json
            json_data = json.loads(data) if isinstance(data, str) else data
            response = requests.request(method, url, json=json_data, headers=headers,
                                    timeout=timeout, verify=False, proxies=core.config.proxies)
        else:
            response = requests.request(method, url, data=data, headers=headers,
                                     timeout=timeout, verify=False, proxies=core.config.proxies)
        return response
    except ProtocolError:
        logger.warning('WAF is dropping suspicious requests.')
        logger.warning('Scanning will continue after 10 minutes.')
        time.sleep(600)
    except Exception as e:
        logger.warning('Unable to connect to the target.')
        return requests.Response()
