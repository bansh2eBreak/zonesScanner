# -*- coding: utf-8 -*-

import json
import requests
import logging
import fofa

class FofaScan:
    def __init__(self, config_reader):
        self.domains = config_reader.get_value('Scanner', 'domains').split(',')
        self.email = config_reader.get_value('Scanner', 'email')
        self.key = config_reader.get_value('Scanner', 'key')
        self.splunk_authorization = config_reader.get_value('Splunk', 'Authorization')
        self.api_url = config_reader.get_value('API', 'url')
        # self.config = configparser.ConfigParser()
        # # 读取配置文件
        # self.config.read(config_file)
        # self.domains = self.config.get('Scanner', 'domains').split(',')
        # self.email = self.config.get('Scanner', 'email')
        # self.key = self.config.get('Scanner', 'key')
        # self.splunk_authorization = self.config.get('Splunk', 'Authorization')

        # 配置日志记录


    def search_domain(self, query_str, size, page):
        client = fofa.Client(self.email, self.key)
        # cname_domain/cname字段需商业版本
        data = client.search(query_str, size=size, page=page, fields="host,ip,protocol,port,link,title")
        logging.info("Fofa search successfully, query_str is %s" % query_str)
        print(data["results"])
        return data["results"]

    def submit_data(self, data):
        #api_url = self.config.get('API', 'url')
        #splunk_authorization = self.config.get('Splunk', 'Authorization')
        headers = {"Content-Type": "application/json",
                   "Authorization": self.splunk_authorization}

        payload = {
            "event": json.dumps(data),
            "index": "test"
        }
        try:
            response = requests.post(self.api_url, data=json.dumps(payload), headers=headers)
            response.raise_for_status()
            logging.info("Data submitted successfully!")
        except requests.exceptions.RequestException as e:
            logging.error("Failed to submit data: %s" % str(e))
        except json.JSONDecodeError as e:
            logging.error("Failed to convert data to JSON: %s" % str(e))

    def scanner(self):
        for domain in self.domains:
            query_str = f'domain="{domain}"'
            logging.info("start search：%s" % domain)
            results = self.search_domain(query_str, size=100, page=1)
            for host, ip, protocol, port, link, title in results:
                json_data = {
                    "log_source": "fofa",
                    "subdomain": host,
                    "ip": ip,
                    "protocol": protocol,
                    "port": port,
                    "link": link,
                    "title": title
                }
                #print(json_data)
                self.submit_data(json_data)
            logging.info("end search：%s" % domain)