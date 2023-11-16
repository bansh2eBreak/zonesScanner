# -*- coding: utf-8 -*-

import configparser

class ConfigReader:
    def __init__(self, file_path):
        self.config = configparser.ConfigParser()
        self.config.read(file_path)

    def get_value(self, section, key):
        return self.config.get(section, key)