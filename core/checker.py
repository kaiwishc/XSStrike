import copy
from fuzzywuzzy import fuzz
import re
from urllib.parse import unquote

from core.config import xsschecker
from core.requester import requester
from core.utils import replaceValue, fillHoles


def checker(url, params, headers, method, delay, payload, positions, timeout, encoding):
    checkString = 'st4r7s' + payload + '3nd'
    if encoding:
        checkString = encoding(unquote(checkString))
    response = requester(url, replaceValue(
        params, xsschecker, checkString, copy.deepcopy), headers, method, delay, timeout).text.lower()
    reflectedPositions = []
    for match in re.finditer('st4r7s', response):
        reflectedPositions.append(match.start())
    filledPositions = fillHoles(positions, reflectedPositions)
    #  Itretating over the reflections
    num = 0
    efficiencies = []
    reflected_snippets = []
    for position in filledPositions:
        allEfficiencies = []
        snippet = ""
        try:
            start = max(0, reflectedPositions[num] - 50)
            end = min(len(response), reflectedPositions[num] + len(checkString) + 50)
            reflected = response[reflectedPositions[num]
                :reflectedPositions[num]+len(checkString)]
            snippet = response[start:end]
            efficiency = fuzz.partial_ratio(reflected, checkString.lower())
            allEfficiencies.append(efficiency)
        except IndexError:
            pass
        if position:
            start = max(0, position - 50)
            end = min(len(response), position + len(checkString) + 50)
            reflected = response[position:position+len(checkString)]
            if not snippet:
                snippet = response[start:end]
            if encoding:
                checkString = encoding(checkString.lower())
            efficiency = fuzz.partial_ratio(reflected, checkString)
            if reflected[:-2] == ('\\%s' % checkString.replace('st4r7s', '').replace('3nd', '')):
                efficiency = 90
            allEfficiencies.append(efficiency)
            efficiencies.append(max(allEfficiencies))
            reflected_snippets.append(snippet)
        else:
            efficiencies.append(0)
            reflected_snippets.append("")
        num += 1
    return efficiencies, reflected_snippets
