# 自动化采集并扫描域名资产工具

自动化采集公司的域名资产，涉及Comlaude、CloudFlare、Aws三个DNS服务商，并且自动化扫描检测域名违规对外暴露的情况。功能主要是：

1、从Comlaude、CloudFlare、Aws同步公司域名资产
2、从Fofa网络空间扫描公司资产，扫描方式：一级域名+证书
3、通过httpx检测违规暴露的的域名资产