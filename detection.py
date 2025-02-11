import os
import re
import math
from indicators import *
from functions import *

result_count = 0
result_files = 0

def shannon_entropy(data, iterator):
  
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def analysis(path, plain):
    global result_count
    global result_files
    result_files += 1
    with open(path, 'r', encoding='utf-8', errors='replace') as content_file:

        content = content_file.read()
        content = clean_source_and_format(content)

        credz = ['pass', 'secret', 'token', 'pwd']
        for credential in credz:
            content_pure = content.replace(' ', '')

            regex_var_detect = "\$[\w\s]+\s?=\s?[\"|'].[\"|']|define\([\"|'].[\"|']\)"
            regex = re.compile(regex_var_detect , re.I)
            matches = regex.findall(content_pure)
            
            for vuln_content in matches:
                if credential in vuln_content.lower():
                    payload = ["", "Hardcoded Credential", []]
                    add_vuln_var(payload, plain, path, vuln_content, content, regex_var_detect)

        
        content_pure = content.replace(' ', '')
        regex_var_detect = ".?=\s?[\"|'].?[\"|'].*?"
        regex = re.compile(regex_var_detect , re.I)
        matches = regex.findall(content_pure)
        BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        HEX_CHARS = "1234567890abcdefABCDEF"

        for vuln_content in matches:
            payload = ["", "High Entropy String", []]
            if shannon_entropy(vuln_content, BASE64_CHARS) >= 4.1 or \
                shannon_entropy(vuln_content, HEX_CHARS) >= 2.5:
                add_vuln_var(payload, plain, path, vuln_content, content, regex_var_detect)
                
        
        for payload in payloads:
            regex = re.compile(payload[0] + regex_indicators)
            matches = regex.findall(content.replace(" ", "(PLACEHOLDER"))

            for vuln_content in matches:

                vuln_content = list(vuln_content)
                for i in range(len(vuln_content)):
                    vuln_content[i] = vuln_content[i].replace("(PLACEHOLDER", " ")
                    vuln_content[i] = vuln_content[i].replace("PLACEHOLDER", "")

                occurence = 0

                if not check_protection(payload[2], vuln_content):
                    declaration_text, line = "", ""

                    sentence = "".join(vuln_content)
                    regex = re.compile(regex_indicators[2:-2])
                    for vulnerable_var in regex.findall(sentence):
                        false_positive = False
                        occurence += 1

                        if not check_exception(vulnerable_var[1]):
                            false_positive, declaration_text, line = check_declaration(
                                content,
                                vulnerable_var[1],
                                path)

                            is_protected = check_protection(payload[2], declaration_text)
                            false_positive = is_protected if is_protected else false_positive

                        line_vuln = find_line_vuln(payload, vuln_content, content)

                        if "$_" not in vulnerable_var[1]:
                            if "$" not in declaration_text.replace(vulnerable_var[1], ''):
                                false_positive = True

                        if not false_positive:
                            result_count = result_count + 1
                            display(path, payload, vuln_content, line_vuln, declaration_text, line, vulnerable_var[1], occurence, plain)


def recursive(dir, progress, plain):
    progress += 1
    progress_indicator = '⬛'
    if plain:
        progress_indicator = "█"
    try:
        for name in os.listdir(dir):

            print('\tAnalyzing : ' + progress_indicator * progress + '\r', end="\r"),

            if os.path.isfile(os.path.join(dir, name)):
                if ".php" in os.path.join(dir, name):
                    analysis(dir + "/" + name, plain)
            else:
                recursive(dir + "/" + name, progress, plain)

    except OSError as e:
        print("Error 404 - Not Found, maybe you need more right ?" + " " * 30)
        exit(-1)


def scanresults():
    global result_count
    global result_files
    print("Found {} vulnerabilities in {} files".format(result_count, result_files))



def add_vuln_var(payload, plain, path, vuln_content, page_content, regex_var_detect, occurence=1):
    line_vuln = -1
    splitted_content = page_content.split('\n')
    for i in range(len(splitted_content)):
        regex = re.compile(regex_var_detect, re.I)
        matches = regex.findall(splitted_content[i])
        if len(matches) > 0:
            line_vuln = i

    display(
        path,           # path
        payload,        # payload
        vuln_content,   # vulnerability
        line_vuln,      # line
        vuln_content,   # declaration_text
        str(line_vuln), # declaration_line
        vuln_content,   # colored
        occurence,      # occurence
        plain           # plain
    )

    global result_count
    result_count = result_count + 1