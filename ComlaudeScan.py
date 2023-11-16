# -*- coding: utf-8 -*-

import boto3
from botocore.config import Config
import json
import requests
import logging

import requests
import json
import logging

class ComlaudeScan:
    def __init__(self, config_reader):
        self.username = config_reader.get_value('comlaude', 'username')
        self.password = config_reader.get_value('comlaude', 'password')
        self.groupid = config_reader.get_value('comlaude', 'groupid')
        self.apikey = config_reader.get_value('comlaude', 'apikey')
        self.splunk_authorization = config_reader.get_value('Splunk', 'Authorization')
        self.api_url = config_reader.get_value('API', 'url')

    def get_access_token(self):
        url = "https://api.comlaude.com/api_login"  # 替换为实际的 API 接口地址
        headers = {
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {
            "username": self.username,
            "password": self.password,
            "api_key": self.apikey
        }
        try:
            response = requests.post(url, headers=headers, data=data)
            response.raise_for_status()
            json_data = response.json()
            access_token = json_data["data"]["access_token"]
            logging.info("Comlaude login api request successful!")
            return access_token
        except requests.exceptions.RequestException as e:
            logging.info("Comlaude Failed to retrieve access token: %s" % str(e))
        except json.JSONDecodeError as e:
            logging.info("Comlaude Failed to decode JSON response: %s " % str(e))

    def search_domain(self, token):

        api_url = "https://api.comlaude.com/groups/%s/domains/zones/records?limit=1000" % self.groupid

        headers = {
            "accept": "application/json",
            "Authorization": f"Bearer {token}"
        }

        try:
            response = requests.get(api_url, headers=headers)
            response.raise_for_status()
            data = response.json().get('data')
            logging.info("Comlaude /groups/%s/domains/zones/records api request successful!")
            return data
        except requests.exceptions.RequestException as e:
            logging.info("Comlaude Failed to retrieve domain info: %s" %str(e))
        except json.JSONDecodeError as e:
            logging.info("Comlaude Failed to decode JSON response: %s" %str(e))

    def submit_data(self, data):
        # 遍历结果列表并获取id和name字段
        for item in data:
            domain_id = item['zone']['domain']['id']
            domain_name = item['zone']['domain']['name']
            subdomain = item['name']
            subdomain_type = item['type']
            zone_id = item['zone']['id']
            zone_signed = item['zone']['signed']
            locked = item['locked']
            subdomain_content = item['value']
            json_data = {
                "log_source": "comlaude",
                "domain_id": domain_id,
                "domain_name": domain_name,
                "zone_id": zone_id,
                "zone_signed": zone_signed,
                "locked": locked,
                "subdomain_type": subdomain_type,
                "subdomain": subdomain,
                "subdomain_content": subdomain_content
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
                logging.info("Comlaude Data submitted successfully! subdomain is %s " % subdomain)
            except requests.exceptions.RequestException as e:
                logging.error("Comlaude Failed to submit data: %s" % str(e))
            except json.JSONDecodeError as e:
                logging.error("Comlaude Failed to convert data to JSON: %s" % str(e))

    def scanner(self):
        token = self.get_access_token()
        domain_result = self.search_domain(token)
        self.submit_data(domain_result)