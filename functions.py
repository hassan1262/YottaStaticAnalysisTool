import os
import re


def nth_replace(string, old, new, n):
    if string.count(old) >= n:
        left_join = old
        right_join = old
        groups = string.split(old)
        nth_split = [left_join.join(groups[:n]), right_join.join(groups[n:])]
        return new.join(nth_split)
    return string.replace(old, new)


def display(path, payload, vulnerability, line, declaration_text, declaration_line, colored, occurrence, plain):
    header = "{}Potential vulnerability found : {}{}{}".format('' if plain else '\033[1m', '' if plain else '\033[92m', payload[1], '' if plain else '\033[0m')

    line = "n°{}{}{} in {}".format('' if plain else '\033[92m', line, '' if plain else '\033[0m', path)

    vuln = nth_replace("".join(vulnerability), colored, "{}".format('' if plain else '\033[92m') + colored + "{}".format('' if plain else '\033[0m'), occurrence)
    vuln = "{}({})".format(payload[0], vuln)

    rows, columns = os.popen('stty size', 'r').read().split()
    print("-" * (int(columns) - 1))
    print("Name        \t{}".format(header))
    print("-" * (int(columns) - 1))
    print("{}Line {}             {}".format('' if plain else '\033[1m', '' if plain else '\033[0m', line))
    print("{}Code {}             {}".format('' if plain else '\033[1m', '' if plain else '\033[0m', vuln))

    if "$_" not in colored:
        declared = "Undeclared in the file"
        if declaration_text != "":
            declared = "Line n°{}{}{} : {}".format('' if plain else '\033[0;92m', declaration_line, '' if plain else '\033[0m', declaration_text)

        print("{}Declaration {}      {}".format('' if plain else '\033[1m', '' if plain else '\033[0m', declared))

    print("")


def find_line_vuln(payload, vulnerability, content):
    content = content.split('\n')
    for i in range(len(content)):
        if payload[0] + '(' + vulnerability[0] + vulnerability[1] + vulnerability[2] + ')' in content[i]:
            return str(i - 1)
    return "-1"


def find_line_declaration(declaration, content):
    content = content.split('\n')
    for i in range(len(content)):
        if declaration in content[i]:
            return str(i)
    return "-1"


def clean_source_and_format(content):
    content = content.replace("    ", " ")

    content = content.replace("echo ", "echo(")
    content = content.replace(";", ");")
    return content


def check_protection(payload, match):
    for protection in payload:
        if protection in "".join(match):
            return True
    return False


def check_exception(match):
    exceptions = ["_GET", "_REQUEST", "_POST", "_COOKIES", "_FILES"]
    for exception in exceptions:
        if exception in match:
            return True
    return False


def check_declaration(content, vuln, path):
    regex_declaration = re.compile("(include.*?|require.*?)\\([\"\'](.*?)[\"\']\\)")
    includes = regex_declaration.findall(content)

    for include in includes:
        relative_include = os.path.dirname(path) + "/"
        try:
            path_include = relative_include + include[1]
            with open(path_include, 'r') as f:
                content = f.read() + content
        except Exception as e:
            return False, "", ""

    vulnerability = vuln[1:].replace(')', '\\)').replace('(', '\\(')
    regex_declaration2 = re.compile("\\$(.*?)([\t ]*)as(?!=)([\t ]*)\\$" + vulnerability)
    declaration2 = regex_declaration2.findall(content)
    if len(declaration2) > 0:
        return check_declaration(content, "$" + declaration2[0][0], path)

    regex_declaration = re.compile("\\$" + vulnerability + "([\t ]*)=(?!=)(.*)")
    declaration = regex_declaration.findall(content)
    if len(declaration) > 0:

        declaration_text = "$" + vulnerability + declaration[0][0] + "=" + declaration[0][1]
        line_declaration = find_line_declaration(declaration_text, content)
        regex_constant = re.compile("\\$" + vuln[1:] + "([\t ]*)=[\t ]*?([\"\'(]*?[a-zA-Z0-9{}_\\(\\)@\\.,!: ]*?[\"\')]*?);")
        false_positive = regex_constant.match(declaration_text)

        if false_positive:
            return True, "", ""
        return False, declaration_text, line_declaration

    return False, "", ""