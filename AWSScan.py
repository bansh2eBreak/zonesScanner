# -*- coding: utf-8 -*-

import boto3
from botocore.config import Config
import json
import requests
import logging

class AWSScan:
    def __init__(self, config_reader):
        self.splunk_authorization = config_reader.get_value('Splunk', 'Authorization')
        self.api_url = config_reader.get_value('API', 'url')
        self.my_config = Config(
            region_name='us-east-1',
            signature_version='v4',
            retries={
                'max_attempts': 10,
                'mode': 'standard'
            }
        )

    def search_domain(self):
        session = boto3.Session(profile_name='Aws-DNS')
        route53_client = session.client('route53', config=self.my_config)
        hosted_zones = route53_client.list_hosted_zones()['HostedZones']
        logging.info("route53_client.list_hosted_zones() call successfully!")

        for zone in hosted_zones:
            zone_id = zone['Id']
            zone_name = zone['Name'].rstrip('.')
            privatezone = zone['Config']['PrivateZone']
            record_sets = route53_client.list_resource_record_sets(HostedZoneId=zone_id)['ResourceRecordSets']

            for record_set in record_sets:
                subdomain = record_set['Name'].rstrip('.')
                subdomain_type = record_set['Type']
                subdomain_content = record_set.get('ResourceRecords')
                record_data = {
                    "log_source": "aws",
                    "zone_id": zone_id,
                    "zone_name": zone_name,
                    "PrivateZone": privatezone,
                    "subdomain_type": subdomain_type,
                    "subdomain": subdomain,
                    "subdomain_content": subdomain_content
                }
                self.submit_data(record_data)

    def submit_data(self, data):
        headers = {
            "Content-Type": "application/json",
            "Authorization": self.splunk_authorization
        }

        payload = {
            "event": json.dumps(data),
            "index": "test"
        }

        try:
            response = requests.post(self.api_url, data=json.dumps(payload), headers=headers)
            response.raise_for_status()
            logging.info("AWS Data submitted successfully! subdomain is %s" % data['subdomain'])
        except requests.exceptions.RequestException as e:
            logging.error("AWS Failed to submit! data: %s" % str(e))
        except json.JSONDecodeError as e:
            logging.error("AWS Failed to convert data to JSON: %s" % str(e))
