#!/usr/bin/env python 
# -*- coding:utf-8 -*-
import yara
import os
import sys
import time
import requests
import spiderUrls
import Queue
import threading

cnt = 0
dicts = {}

class threadRequest(threading.Thread):
    def __init__(self, queue, rule):
        threading.Thread.__init__(self)
        self.queue = queue
        self.rule = rule

    # 请求构造的url内容
    def getUrlContent(self, url):
        # print url
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
            content = r.text
            if r.status_code == 200:
                # print content
                return content.encode(encoding="utf-8")
        except:
            pass
        return

    # 扫描结果处理
    def processResult(self, result, url):
        dict = {}
        for key in result:
            for dic in result[key]:
                lis = dic['strings']
                for i, k in enumerate(lis):
                    print i, repr(k['data'])
                    dict[i] = str(k['data'])
        global dicts
        dicts[url] = dict

    def run(self):
        while True:
            try:
                url = self.queue.get()
            except:
                 break;
            try:
                # 退出信号
                if url == -1:
                    self.queue.task_done()
                    break;
            except:
                self.queue.task_done()
                break
            try:
                content = self.getUrlContent(url)
                if content:
                    matches = self.rule.match(data=content)
                    if len(matches) > 0:
                        print matches
                        print url
                        # lock.release()
                        global cnt
                        cnt += 1
                        self.processResult(matches, url)
                        # lock.release()
            except Exception, e:
                print e
            finally:
                self.queue.task_done()

class DetectShell:
    def __init__(self, url, script):
        self.thread_num = 20
        self.queue = Queue.Queue(self.thread_num * 2)
        self.url = url
        self.script = script.lower()

    def getScript(self):
        str = self.script
        if str == "jsp":
            return "jsp"
        elif str == "php":
            return "php"
        elif str == "asp":
            return "asp"
        elif str == "aspx":
            return "aspx"

    # 将yara规则编译
    def getRules(self, path):
        index = 0
        filepath = {}
        for dirpath, dirs, files in os.walk(path):
            for file in files:
                ypath = os.path.join(dirpath, file)
                key = "rule" + str(index)
                filepath[key] = ypath
                index += 1
        yararule = yara.compile(filepaths=filepath)
        return yararule

    # 检测webshell
    def check(self, rule):
        spider = spiderUrls.SpiderUrls(self.url)
        urllist = spider.crawler()
        spider.writetofile(urllist)
        list = spider.path_list
        thread_list = {}
        for i in range(0, self.thread_num):
            try:
                t = threadRequest(self.queue, rule)
                t.setDaemon(True)
                t.start()
                thread_list.append(t)
                del t
            except:
                pass
        dicpath = "dic/" + self.getScript()
        print dicpath
        for line in open(dicpath):
            line = line.strip()  # 去掉行末尾的换行符，否则即使有资源也返回404
            print "--------------------", line
            for upath in list:
                url = upath + line
                # print url
                self.queue.put(url)
        self.queue.join()
        # 结束线程
        for i in range(0, len(thread_list)):
            self.queue.put(-1)
        self.queue.join()


if __name__ == '__main__':
    time_start = time.time()
    # 测试
    cnt = 0
    if len(sys.argv) == 1:
        url = "http://www.rongji.com"
    elif len(sys.argv[1]):
        url = sys.argv[1]
    if sys.argv[2]:
        scriptType = sys.argv[2]
    else:
        exit(0)
    rulepath = sys.path[0] + "/rules"  # yara规则目录
    # malpath = sys.path[0] + "/webshell"  # 待检测目录
    detect = DetectShell(url, scriptType)
    yararule = detect.getRules(rulepath)
    detect.check(yararule)
    print "cnt:", cnt
    for key in dicts:
        print key
        print dicts[key]
    time_end = time.time()
    print "totaly time: ", time_end - time_start
