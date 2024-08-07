import pandas as pd
import re
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress

# 映射字典
MAP_DICT = {
    'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
    'DOMAIN-KEYWORD': 'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword', 'IP-CIDR': 'ip_cidr',
    'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'IP6-CIDR': 'ip_cidr', 'SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip',
    'DST-PORT': 'port', 'SRC-PORT': 'source_port', 'URL-REGEX': 'domain_regex', 'DOMAIN-REGEX': 'domain_regex', 'PROCESS-NAME': 'process_name'
}

def read_yaml_from_url(url):
    response = requests.get(url)
    response.raise_for_status()
    yaml_data = yaml.safe_load(response.text)
    return yaml_data

def read_list_from_url(url):
    df = pd.read_csv(url, header=None, names=['pattern', 'address', 'other', 'other2', 'other3'])
    filtered_rows = []
    rules = []
    if 'AND' in df['pattern'].values:
        and_rows = df[df['pattern'].str.contains('AND', na=False)]
        for _, row in and_rows.iterrows():
            rule = {
                "type": "logical",
                "mode": "and",
                "rules": []
            }
            pattern = ",".join(row.values.astype(str))
            components = re.findall(r'\((.*?)\)', pattern)
            for component in components:
                for keyword in MAP_DICT.keys():
                    if keyword in component:
                        match = re.search(f'{keyword},(.*)', component)
                        if match:
                            value = match.group(1)
                            rule["rules"].append({
                                MAP_DICT[keyword]: value
                            })
            rules.append(rule)
    for index, row in df.iterrows():
        if 'AND' not in row['pattern']:
            filtered_rows.append(row)
    df_filtered = pd.DataFrame(filtered_rows, columns=['pattern', 'address', 'other', 'other2', 'other3'])
    return df_filtered, rules

def is_ipv4_or_ipv6(address):
    try:
        ipaddress.IPv4Network(address)
        return 'ipv4'
    except ValueError:
        try:
            ipaddress.IPv6Network(address)
            return 'ipv6'
        except ValueError:
            return None

def parse_and_convert_to_dataframe(link):
    rules = []
    if link.endswith('.yaml') or link.endswith('.txt'):
        try:
            yaml_data = read_yaml_from_url(link)
            rows = []
            if not isinstance(yaml_data, str):
                items = yaml_data.get('payload', [])
            else:
                lines = yaml_data.splitlines()
                line_content = lines[0]
                items = line_content.split()
            for item in items:
                address = item.strip("'")
                if ',' not in item:
                    if is_ipv4_or_ipv6(item):
                        pattern = 'IP-CIDR'
                    else:
                        if address.startswith('+') or address.startswith('.'):
                            pattern = 'DOMAIN-SUFFIX'
                            address = address[1:]
                            if address.startswith('.'):
                                address = address[1:]
                        else:
                            pattern = 'DOMAIN'
                else:
                    pattern, address = item.split(',', 1)
                rows.append({'pattern': pattern.strip(), 'address': address.strip(), 'other': None})
            df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
        except:
            df, rules = read_list_from_url(link)
    else:
        df, rules = read_list_from_url(link)
    return df, rules

def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0])
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj

def parse_list_file(link):
    try:
        df, rules = parse_and_convert_to_dataframe(link)
        return df, rules
    except:
        print(f'获取链接出错，已跳过：{link}')
        return pd.DataFrame(), []

def get_version(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('version', 1)
    return 1

with open("../links.txt", 'r') as links_file:
    links = links_file.read().splitlines()

links = [l for l in links if l.strip() and not l.strip().startswith("#")]

output_dir = "./"
results = {}

with concurrent.futures.ThreadPoolExecutor() as executor:
    future_to_link = {executor.submit(parse_list_file, link): link for link in links}
    for future in concurrent.futures.as_completed(future_to_link):
        link = future_to_link[future]
        try:
            df, rules = future.result()
            base_name = os.path.basename(link).split('.')[0]
            if base_name not in results:
                results[base_name] = {'df': pd.DataFrame(), 'rules': []}
            results[base_name]['df'] = pd.concat([results[base_name]['df'], df], ignore_index=True)
            results[base_name]['rules'].extend(rules)
        except Exception as e:
            print(f'链接 {link} 处理失败: {e}')

for base_name, data in results.items():
    df = data['df']
    rules_list = data['rules']
    df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)
    df = df[df['pattern'].isin(MAP_DICT.keys())].reset_index(drop=True)
    df = df.drop_duplicates().reset_index(drop=True)
    df['pattern'] = df['pattern'].replace(MAP_DICT)
    os.makedirs(output_dir, exist_ok=True)

    file_name = os.path.join(output_dir, f"{base_name}.json")
    version = get_version(file_name)

    result_rules = {"version": version, "rules": []}
    domain_entries = []
    for pattern, addresses in df.groupby('pattern')['address'].apply(list).to_dict().items():
        if pattern == 'domain_suffix':
            rule_entry = {pattern: [address.strip() for address in addresses]}
            result_rules["rules"].append(rule_entry)
        elif pattern == 'domain':
            domain_entries.extend([address.strip() for address in addresses])
        else:
            rule_entry = {pattern: [address.strip() for address in addresses]}
            result_rules["rules"].append(rule_entry)
    domain_entries = list(set(domain_entries))
    if domain_entries:
        result_rules["rules"].insert(0, {'domain': domain_entries})

    """
    if rules_list != []:
        result_rules["rules"].extend(rules_list)
    """

    with open(file_name, 'w', encoding='utf-8') as output_file:
        result_rules_str = json.dumps(sort_dict(result_rules), ensure_ascii=False, indent=2)
        result_rules_str = result_rules_str.replace('\\\\', '\\')
        output_file.write(result_rules_str)

    srs_path = file_name.replace(".json", ".srs")
    os.system(f"sing-box rule-set compile --output {srs_path} {file_name}")

# 打印生成的文件名
# for file_name in result_file_names:
    # print(file_name)
