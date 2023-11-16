# -*- coding: utf-8 -*-

import logging
from FofaScan import FofaScan
from CloudFlareScan import CloudflareScanner
from ConfigReader import ConfigReader
from AWSScan import AWSScan
from ComlaudeScan import ComlaudeScan

def main():
    # 读取配置文件
    config_file = './conf/config.ini'
    config_reader = ConfigReader(config_file)

    # 设置日志配置
    #logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.basicConfig(filename='./log/scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # 创建 CloudflareScanner 实例并执行扫描
    logging.info("创建 CloudflareScanner 实例并执行扫描")
    cfscanner = CloudflareScanner(config_reader)
    cfscanner.scanner()

    # 创建 AWSScan 实例并执行扫描
    logging.info("创建 AWSScan 实例并执行扫描")
    awsscanner = AWSScan(config_reader)
    awsscanner.search_domain()

    # 创建 ComlaudeScan 实例并执行扫描
    logging.info("创建 ComlaudeScan 实例并执行扫描")
    comlaudeScan = ComlaudeScan(config_reader)
    comlaudeScan.scanner()

    # 创建 FofaScan 实例并执行扫描
    #fofascanner = FofaScan(config_reader)
    #fofascanner.scanner()

if __name__ == "__main__":
    main()