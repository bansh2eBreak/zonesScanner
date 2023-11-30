# -*- coding: utf-8 -*-

import logging
from FofaScan import FofaScan
from CloudFlareScan import CloudflareScanner
from ConfigReader import ConfigReader
from AWSScan import AWSScan
from ComlaudeScan import ComlaudeScan
import datetime

def main():
    # 读取配置文件
    config_file = './conf/config.ini'
    config_reader = ConfigReader(config_file)

    # 获取当前日期
    current_date = datetime.date.today().strftime("%Y%m%d")

    # 定义文件路径和名称
    output_file = f"./log/subdomains_{current_date}.txt"

    # 设置日志配置
    #logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.basicConfig(filename='./log/scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # 创建 CloudflareScanner 实例并执行扫描
    logging.info("创建 CloudflareScanner 实例并执行扫描")

    # 创建并打开文件
    file = open(output_file, "a")

    cfscanner = CloudflareScanner(config_reader, file)
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
    fofascanner = FofaScan(config_reader)
    fofascanner.scanner()

    # 关闭文件
    file.close()

if __name__ == "__main__":
    main()