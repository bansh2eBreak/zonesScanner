# -*- coding: utf-8 -*-

import requests
import json
import logging

class CloudflareScanner:
    def __init__(self, config_reader):
        self.cf_authorization = config_reader.get_value('cloudflare', 'Authorization')
        self.splunk_authorization = config_reader.get_value('Splunk', 'Authorization')
        self.api_url = config_reader.get_value('API', 'url')

    def search_domain(self):
        # 设置请求头
        headers = {
            'Authorization': self.cf_authorization,
            'Content-Type': 'application/json'
        }

        # 发起API请求
        url = 'https://api.cloudflare.com/client/v4/zones'
        response = requests.get(url, headers=headers)

        # 检查响应状态码
        if response.status_code == 200:
            # 解析JSON响应
            data = response.json()
            result = data['result']
            logging.info("CloudFlare API(/client/v4/zones) request successful!")
            return result
        else:
            #print(f"API请求失败. 状态码: {response.status_code}")
            logging.info("CloudFlare API(/client/v4/zones) request failed, error code is %s" % response.status_code)

    def search_dns_records(self, data):
        # 设置请求头
        headers = {
            'Authorization': self.cf_authorization,
            'Content-Type': 'application/json'
        }

        all_domain_data = []

        # 遍历结果列表并获取id和name字段
        for item in data:
            zone_id = item['id']

            # 发起API请求
            url = 'https://api.cloudflare.com/client/v4/zones/%s/dns_records' % zone_id
            response = requests.get(url, headers=headers)

            # 检查响应状态码
            if response.status_code == 200:
                # 解析JSON响应
                data = response.json()
                result = data['result']
                all_domain_data.append(result)
                logging.info("CloudFlare API(/client/v4/zones/%s/dns_records) request successful!" % zone_id)
            else:
                #print(f"API请求失败. 状态码: {response.status_code}")
                logging.info("CloudFlare API(/client/v4/zones/%s/dns_records) request failed, error code is %s" % (zone_id, response.status_code,))

        all_domain_data_json = json.dumps(all_domain_data)
        return all_domain_data_json

    def submit_data(self, data):
        all_domain_data_list = json.loads(data)

        for domain_data in all_domain_data_list:
            # 遍历结果列表并获取id和name字段
            for item in domain_data:
                zone_id = item['zone_id']
                zone_name = item['zone_name']
                subdomain = item['name']
                subdomain_type = item['type']
                subdomain_content = item['content']
                created_time = item['created_on']
                modified_time = item['modified_on']
                json_data = {
                    "log_source": "cloudflare",
                    "zone_id": zone_id,
                    "zone_name": zone_name,
                    "subdomain": subdomain,
                    "subdomain_type": subdomain_type,
                    "subdomain_content": subdomain_content,
                    "created_time": created_time,
                    "modified_time": modified_time
                }

                headers = {"Content-Type": "application/json",
                           "Authorization": self.splunk_authorization}

                payload = {
                    "event": json.dumps(json_data),
                    "index": "test"
                }

                try:
                    response = requests.post(self.api_url, data=json.dumps(payload), headers=headers)
                    response.raise_for_status()
                    logging.info("CloudFlare Data submitted successfully! subdomain is %s" % subdomain)
                except requests.exceptions.RequestException as e:
                    logging.error("CloudFlare Failed to submit! data: %s" % str(e))
                except json.JSONDecodeError as e:
                    logging.error("CloudFlare Failed to convert data to JSON: %s" % str(e))

    def scanner(self):
        zone_data = self.search_domain()
        dns_records = self.search_dns_records(zone_data)
        self.submit_data(dns_records)