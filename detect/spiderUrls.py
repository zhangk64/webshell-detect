#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#######
# 2018-12-27 To zhangkai
# 目前只爬取<a href= 的链接，暂不支持img，css，js等
#######

import requests
import re
import urlparse

class SpiderUrls():
    def __init__(self, url):
        self.urlList = [url]
        result = urlparse.urlparse(url)
        self.domain = result.netloc
        self.protocol = result.scheme
        self.origin_url = self.protocol + "://" + self.domain
        self.path_list = []  # 提取目录

    # url过滤
    def url_filter(self, urllist):
        urls = []
        for l in urllist:
            if re.findall(r"http", l):
                urls.append(l)
                continue
            if re.findall(r'.*/.*', l):  # 防止出现类似 <a href="/ar/2014042899000006.htm">电子政务 </a> 不完整url的情况
                if l[0] == '/':
                    l = self.origin_url + l
                else:
                    l = self.origin_url + '/' + l
                urls.append(l)

        # print urls
        url_list = []
        for l in urls:
            if re.findall(self.domain, l):  # 去除其它域的url
                if l not in url_list:
                    url_list.append(l)
        # print urls
        return url_list

    # 提取页面url
    def spiderpage(self, url):
        pagelinks = []
        try:
            header = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                'Connection': 'keep-alive',
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36'
            }
            r = requests.get(url, headers=header)
            r.encoding = "utf-8"
            pagetext = r.text
            # 去掉空格便于正则
            pagetext = pagetext.replace(' ', '')
            # print pagetext

            # 正则表达式表示要爬取的是<a href="和"中的内容,"或'都可以,即当前页面下所有的链接url,返回列表
            pagelinks = re.findall(r'(?<=<ahref=\").+?(?=\")|(?<=<ahref=\').+?(?=\')', pagetext)
            # print pagelinks
        except:
            pass
        return pagelinks

    # 采用深度优先搜索（递归）
    def getUrl(self, url):
        print url
        # 爬取当前页面的所有url
        urllist = self.spiderpage(url)
        # 筛选非当前域的url
        if urllist:
            right_urls = self.url_filter(urllist)
        else:
            right_urls = []
        # 添加url到访问过得列表中
        if url not in self.urlList:
            self.urlList.append(url)
        # 递归遍历获得的url
        for u in right_urls:
            if u not in self.urlList:
                self.getUrl(u)

    def crawler(self):
        url = self.urlList[0]
        if url is None or url == '':
            return
        self.getUrl(url)
        if self.origin_url in self.urlList:
            self.urlList.remove(self.origin_url)  # 去掉 http://xxx.xxx.xxx 的链接
        return self.urlList

    # 爬取url写入txt文本
    def writetofile(self, list):
        # 提取网站目录
        for u in list:
            index = -1
            if u[index] != '/':
                index -= 1
                while (u[index] != '/'):
                    index -= 1
                u = u[:index + 1]
            if u not in self.path_list:
                self.path_list.append(u)

        # 将url写入urls.txt文件中
        file = open('urls.txt', 'w')
        for url in list:
            file.write(url + "\n")
        file.close()

        print "The number of the urls:", len(list)
        for u in self.path_list:
            print "path:", u

if __name__ == '__main__':
    # url = "http://192.168.166.119/"
    url = "http://192.168.78.145/"
    # url = "https://feed.watcherlab.com/rules/yara/"
    spider = SpiderUrls(url)
    urllist = spider.crawler()
    spider.writetofile(urllist)
    print spider.path_list

