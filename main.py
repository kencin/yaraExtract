
## 解析Yara规则
import getopt
import sys

import plyara
import os
from plyara.core import Parser

YARA_DIR = ".\yara"
yara_parser = plyara.Plyara()


class YaraParser:
    def __init__(self, input_dir, output_dir, time_div):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.time_div = int(time_div)

    @staticmethod
    def rebuild_yara_rule(rules):
        """Take a parsed yararule and rebuild it into a usable one.

        Args:
            rules: List output from a parsed rule.

        Returns:
            str: Formatted text string of YARA rule.
        """
        formatted_rules = str()
        has_import = str()
        for rule in rules:
            rule_format = "{imports}{scopes}rule {rulename}{tags} {{\n{meta}{strings}{condition}\n}}\n"

            rule_name = rule['rule_name']

            # Rule Imports
            if rule.get('imports') and not has_import:
                unpacked_imports = ['import "{}"\n'.format(entry) for entry in rule['imports']]
                rule_imports = '{}\n'.format(''.join(unpacked_imports))
                has_import = rule_format
            else:
                rule_imports = str()

            # Rule Scopes
            if rule.get('scopes'):
                rule_scopes = '{} '.format(' '.join(rule['scopes']))
            else:
                rule_scopes = str()

            # Rule Tags
            if rule.get('tags'):
                rule_tags = ' : {}'.format(' '.join(rule['tags']))
            else:
                rule_tags = str()

            # Rule Metadata
            if rule.get('metadata'):
                unpacked_meta = []
                kv_list = [(k,) + (v,) for dic in rule['metadata'] for k, v in dic.items()]

                # Check for and handle correctly quoting string metadata
                for k, v in kv_list:
                    if isinstance(v, bool):
                        v = str(v).lower()
                    elif isinstance(v, int):
                        v = str(v)
                    else:
                        v = '"{}"'.format(v)
                    unpacked_meta.append('\n\t\t{key} = {value}'.format(key=k, value=v))
                rule_meta = '\n\tmeta:{}\n'.format(''.join(unpacked_meta))
            else:
                rule_meta = str()

            # Rule Strings
            if rule.get('strings'):

                string_container = list()

                for rule_string in rule['strings']:
                    if 'modifiers' in rule_string:
                        string_modifiers = ' '.join(rule_string['modifiers'])
                        if rule_string['type'] == 'text':
                            string_format = '\n\t\t{} = "{}" {}'
                        else:
                            string_format = '\n\t\t{} = {} {}'
                        fstring = string_format.format(rule_string['name'], rule_string['value'], string_modifiers)
                    else:
                        if rule_string['type'] == 'text':
                            string_format = '\n\t\t{} = "{}"'
                        else:
                            string_format = '\n\t\t{} = {}'
                        fstring = string_format.format(rule_string['name'], rule_string['value'])

                    string_container.append(fstring)

                rule_strings = '\n\tstrings:{}\n'.format(''.join(string_container))
            else:
                rule_strings = str()

            if rule.get('condition_terms'):
                # Format condition with appropriate whitespace between keywords
                cond = list()

                for term in rule['condition_terms']:

                    if not cond:

                        if term in Parser.FUNCTION_KEYWORDS:
                            cond.append(term)

                        elif term in Parser.KEYWORDS:
                            cond.append(term)
                            cond.append(' ')

                        else:
                            cond.append(term)

                    else:

                        if cond[-1] == ' ' and term in Parser.FUNCTION_KEYWORDS:
                            cond.append(term)

                        elif cond and cond[-1] != ' ' and term in Parser.FUNCTION_KEYWORDS:
                            cond.append(' ')
                            cond.append(term)

                        elif cond[-1] == ' ' and term in Parser.KEYWORDS:
                            cond.append(term)
                            cond.append(' ')

                        elif cond and cond[-1] != ' ' and term in Parser.KEYWORDS:
                            cond.append(' ')
                            cond.append(term)
                            cond.append(' ')

                        else:
                            cond.append(term)

                fcondition = ''.join(cond).rstrip(' ')
                rule_condition = '\n\tcondition:\n\t\t{}'.format(fcondition)
            else:
                rule_condition = str()

            formatted_rules += rule_format.format(imports=rule_imports,
                                                rulename=rule_name,
                                                tags=rule_tags,
                                                meta=rule_meta,
                                                scopes=rule_scopes,
                                                strings=rule_strings,
                                                condition=rule_condition)
            formatted_rules += "\n"
        return formatted_rules

    def general_new(self, rules, filename):
        the_new_rules = []
        for rule in rules:
            if "metadata" not in rule:
                return
            for meta in rule["metadata"]:
                if "date" in meta:
                    if not self.compare_date(meta["date"]):
                        the_new_rules.append(rule)
            # print(rule["metadata"])
        with open(os.path.join(self.output_dir, filename), "w") as f:
            f.write(self.rebuild_yara_rule(the_new_rules))

    def search(self, yara_file):
        try:
            with open(yara_file) as f:
                rules = yara_parser.parse_string(f.read())
        except Exception as e:
            print("Error: " + str(e))
            return
        self.general_new(rules, os.path.split(yara_file)[1])

    def run(self):
        for path, dir_list, file_list in os.walk(self.input_dir):
            for file_name in file_list:
                self.search(os.path.join(path, file_name))

    def compare_date(self, date):
        if "/" in date:
            date = date.replace("/", "-")
        if "-" in date:
            for i in date.split("-"):
                if len(i) == 4:
                    return int(i) < self.time_div
            return int("20" + date.split("-")[2]) < self.time_div
        elif "." in date:
            for i in date.split("."):
                if len(i) == 4:
                    return int(i) < self.time_div
        elif " " in date:
            for i in date.split(" "):
                if len(i) == 4:
                    return int(i) < self.time_div
        print(date)


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "i:o:t:", ["help"])
    except getopt.GetoptError:
        print('yaraExtract.exe -h 帮助文档 -i 输入目录 -o 输出目录'
              ' -t 在此年份之前')
        sys.exit(2)
    input_dir, out_put_dir, time_div = str(), str(), str()

    for opt, arg in opts:
        if opt == '-h':
            print('yaraExtract.exe -h 帮助文档 -i 输入目录 -o 输出目录'
                  ' -t 在此年份之前')
            sys.exit()
        elif opt == "-i":
            input_dir = arg
        elif opt == "-o":
            out_put_dir = arg
        elif opt == "-t":
            time_div = arg

    if not input_dir or not out_put_dir or not time_div:
        print("参数有误")
        sys.exit()

    yara_obj = YaraParser(input_dir, out_put_dir, time_div)
    yara_obj.run()

if __name__ == '__main__':
    main(sys.argv[1:])