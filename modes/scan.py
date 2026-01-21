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
from core.utils import getUrl, getParams, getVar, flattenParams
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
        response = requester(url, paramsCopy, headers, method, delay, timeout)
        occurences = htmlParser(response, encoding)
        positions = occurences.keys()
        logger.debug('Scan occurences: {}'.format(occurences))
        if not occurences:
            logger.error('No reflection found')
            continue
        else:
            logger.info('Reflections found: %i' % len(occurences))

        logger.run('Analysing reflections')
        efficiencies = filterChecker(
            url, paramsCopy, headers, method, delay, occurences, timeout, encoding)
        logger.debug('Scan efficiencies: {}'.format(efficiencies))
        logger.run('Generating payloads')
        vectors = generator(occurences, response.text)
        total = 0
        for v in vectors.values():
            total += len(v)
        if total == 0:
            logger.error('No vectors were crafted.')
            continue
        logger.info('Payloads generated: %i' % total)
        progress = 0
        # 标志变量：用于在 skip 模式下跳过当前参数
        skip_current_param = False
        for confidence, vects in vectors.items():
            if skip_current_param:
                break  # 跳出 confidence 循环
            for vect in vects:
                if skip_current_param:
                    break  # 跳出 vect 循环
                if core.config.globalVariables['path']:
                    vect = vect.replace('/', '%2F')
                loggerVector = vect
                progress += 1
                logger.run('Progress: %i/%i\r' % (progress, total))
                if not GET:
                    vect = unquote(vect)
                efficiencies, snippets = checker(
                    url, paramsCopy, headers, method, delay, vect, positions, timeout, encoding)
                if not efficiencies:
                    for i in range(len(occurences)):
                        efficiencies.append(0)
                        snippets.append('')
                bestEfficiency = max(efficiencies)
                
                # Check for stored XSS if verify_url is provided
                stored_xss_found = False
                stored_xss_method = None
                stored_xss_context = None
                
                if core.config.verifyUrl:
                    # Verify stored XSS
                    stored_xss_found, stored_xss_method, stored_xss_context = verify_stored_xss(
                        core.config.verifyUrl,
                        headers,
                        core.config.verifyMethod,
                        vect,
                        delay,
                        timeout,
                        use_js_render=core.config.jsRender
                    )
                    
                    if stored_xss_found:
                        # Stored XSS detected - report it
                        logger.red_line()
                        logger.good('Stored XSS Detected!')
                        logger.good('Payload: %s' % loggerVector)
                        logger.info('Parameter: %s' % paramName)
                        logger.info('Injection URL: %s' % url)
                        logger.info('Verification URL: %s' % core.config.verifyUrl)
                        logger.info('Detection Method: %s' % stored_xss_method)
                        logger.info('Confidence: %i' % confidence)
                        
                        if stored_xss_method and 'interactive' in stored_xss_method:
                            logger.info('Trigger Type: %s (requires user interaction)' % stored_xss_method.replace('interactive_', ''))
                        else:
                            logger.info('Trigger Type: Immediate (on page load)')
                        
                        if stored_xss_context:
                            context_preview = stored_xss_context[:200] if len(stored_xss_context) > 200 else stored_xss_context
                            logger.info('Context: %s' % context_preview.replace('st4r7s', '').replace('3nd', ''))
                        
                        logger.red_line()
                        
                        # For stored XSS, we always want to continue checking other payloads
                        # unless user explicitly stops
                        if not skip:
                            choice = input(
                                '%s Stored XSS found! Would you like to continue scanning? [y/N] ' % que).lower()
                            if choice != 'y':
                                quit()
                        else:
                            # In skip mode, continue to next parameter after finding stored XSS
                            logger.info('Skipping remaining payloads for parameter: %s' % paramName)
                            skip_current_param = True
                            break
                
                # Original reflected XSS detection
                if bestEfficiency > minEfficiency or (vect[0] == '\\' and bestEfficiency >= 95):
                    index = efficiencies.index(bestEfficiency)
                    occurenceList = list(occurences.values())
                    
                    # Safety check: ensure index is within bounds
                    if index >= len(occurenceList) or index >= len(snippets):
                        logger.warning('Index mismatch detected, skipping this payload')
                        continue
                    
                    bestSnippet = snippets[index]
                    bestContext = occurenceList[index]['context']

                    logger.red_line()
                    logger.good('Reflected XSS Detected!' if not stored_xss_found else 'Reflected XSS Also Detected!')
                    logger.good('Payload: %s' % loggerVector)
                    logger.info('Parameter: %s' % paramName)
                    logger.info('Context: %s' % bestContext)
                    logger.info('Efficiency: %i' % bestEfficiency)
                    logger.info('Confidence: %i' % confidence)
                    if GET:
                        logger.info('Reproduction: %s%s' % (url, flattenParams(paramName, params, loggerVector)))
                    
                    # Clean up snippet for display
                    bestSnippet = bestSnippet.replace('st4r7s', '').replace('3nd', '')
                    logger.info('Reflection: %s' % bestSnippet)

                    if bestEfficiency == 100 or (vect[0] == '\\' and bestEfficiency >= 95):
                        if not skip:
                            choice = input(
                                '%s Would you like to continue scanning? [y/N] ' % que).lower()
                            if choice != 'y':
                                quit()
                        else:
                            # skip 模式：发现漏洞后，跳过当前参数，继续扫描下一个参数
                            logger.info('Skipping remaining payloads for parameter: %s' % paramName)
                            skip_current_param = True
                            break  # 跳出 vect 循环
        logger.no_format('')
