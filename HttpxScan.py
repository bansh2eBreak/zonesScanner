# -*- coding: utf-8 -*-

import requests
import subprocess
import json
import datetime
import logging
import configparser

# 配置日志记录
logging.basicConfig(filename='./log/scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 读取配置文件
config = configparser.ConfigParser()
config.read('./conf/config.ini')

splunk_authorization = config.get('Splunk', 'Authorization')
splunk_url = config.get('API', 'url')

# 通过 Splunk 接口获取 subdomain 数据
def get_subdomains_from_file(file_path):
    subdomains = []
    with open(file_path, 'r') as file:
        for line in file:
            subdomain = line.strip()  # 假设每行一个域名，去除首尾空白字符
            subdomains.append(subdomain)
    return subdomains

def scan_domains(subdomains):
    for subdomain in subdomains:
        # 构建扫描命令
        command = ["/root/httpx/httpx", "-u", subdomain, "-title", "-sc", "-ct", "-rt", "-bp", "-server", "-cdn", "-json"]
        try:
            process = subprocess.run(command, capture_output=True, text=True, check=True, timeout=5, stdin=subprocess.DEVNULL)
            logging.info("The httpx command is executed successfully! %s" % subdomain)
            # 获取标准输出和标准错误输出
            stdout = process.stdout.strip()

            # 输出结果
            if stdout:
                # print(stdout)
                data = json.loads(stdout)  # 解析为字典
                data['log_source'] = 'httpxscan'  # 添加新的键值对
                submit_data(data)
            else:
                # 构建json数据：{"timestamp": "2023-11-28T11:13:19.725004+08:00", "input": "www.hashkey.com", "failed": false}
                current_time = datetime.datetime.now().astimezone()
                data = {
                    "timestamp": current_time.isoformat(),
                    "input": subdomain,
                    "log_source": "httpxscan",
                    "failed": True
                }

                submit_data(data)

        except subprocess.TimeoutExpired:
            # 超时处理：构建超时的JSON数据
            current_time = datetime.datetime.now().astimezone()
            data = {
                "timestamp": current_time.isoformat(),
                "input": subdomain,
                "log_source": "httpxscan",
                "failed": True
            }

            submit_data(data)

        except subprocess.CalledProcessError as e:
            print(f"Error occurred while scanning {subdomain}: {e}")

def submit_data(data):
    headers = {"Content-Type": "application/json",
               "Authorization": splunk_authorization}

    payload = {
        "event": json.dumps(data),
        "index": "test"
    }

    print(payload)

    try:
        response = requests.post(splunk_url, data=json.dumps(payload), headers=headers)
        print(response.text)
        response.raise_for_status()
        logging.info("Data submitted successfully! %s" % data["input"])
    except requests.exceptions.RequestException as e:
        logging.error("Failed to submit data: %s" % str(e))
    except json.JSONDecodeError as e:
        logging.error("Failed to convert data to JSON: %s" % str(e))

def main():
    # 获取当前日期
    current_date = datetime.datetime.today().strftime("%Y%m%d")

    # 从文件中获取 subdomain 数据
    file_path = f'/root/DomainScan/log/subdomains_{current_date}.txt'  # 域名数据文件路径
    #print(file_path)
    subdomains = get_subdomains_from_file(file_path)

    # 扫描域名并获取扫描结果
    scan_domains(subdomains)

if __name__ == "__main__":
    main()