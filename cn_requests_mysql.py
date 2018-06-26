import requests
from lxml import etree
import csv
import time
import random
from collections import OrderedDict
import codecs
import pymysql
from datetime import date
from multiprocessing.dummy import Pool as Threadpool


class Cnvdspider(object):
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36"}
        # 如果从某处断线了，可以更改起始的url地址
        self.start_url = "http://www.cnvd.org.cn/flaw/list.htm?max=20&offset=37660"

    def parse(self, url):
        time.sleep(random.randint(1, 2))
        html = requests.get(url, headers=self.headers).content.decode()
        html = etree.HTML(html)
        return html

    def get_list_url(self, html):
        list_url = html.xpath("//div[@id='flawList']/tbody/tr/td[1]/a/@href")
        if list_url is None:
            list_url = html.xpath("//div[@class='blkContainerPblk']//table[@class='tlist']/tbody/tr/td[1]/a/@href")
        for url in list_url:
            url = "http://www.cnvd.org.cn" + url
            self.parse_detaile(url)
        next_url = html.xpath("//a[@class='nextLink']/@href")[0] if html.xpath("//a[@class='nextLink']/@href") else None
        if next_url:
            next_url = "http://www.cnvd.org.cn" + next_url
        return next_url

    def parse_detaile(self, url):
        time.sleep(random.randint(1, 2))
        html = self.parse(url)
        # item = OrderedDict()  # 如果要存入csv文档，建议用有序字典
        item = {}
        # 获取漏洞标题
        item["cn_title"] = html.xpath("//div[@class='blkContainerPblk']/div[@class='blkContainerSblk']/h1/text()")
        if item["cn_title"]:
            item["cn_title"] = html.xpath("//div[@class='blkContainerPblk']/div[@class='blkContainerSblk']/h1/text()")[
                0].strip()
        else:
            item["cn_title"] = 'Null'
            # item["title"] = "".join([i.strip() for i in item["title"]])
        # print(item["title"])
        # 获取漏洞公开日期
        # item["date"] = html.xpath("//td[text()='公开日期']/following-sibling::td[1]/text()")
        item["pub_date"] = html.xpath("//div[@class='tableDiv']/table[@class='gg_detail']//tr[2]/td[2]/text()")
        if item["pub_date"]:
            item["pub_date"] = "".join([i.strip() for i in item["pub_date"]]).replace('-', '')
            item["pub_date"] = self.convertstringtodate(item["pub_date"])
        else:
            item["pub_date"] = '2000-01-01'.replace('-', '')
            item["pub_date"] = self.convertstringtodate(item["pub_date"])
        # 获取漏洞危害级别
        item["hazard_level"] = html.xpath("//td[text()='危害级别']/following-sibling::td[1]/text()")
        if item["hazard_level"]:
            item["hazard_level"] = "".join([i.replace("(", "").replace(")", "").strip() for i in item["hazard_level"]])
        else:
            item["hazard_level"] = 'Null'
        # 获取漏洞影响的产品
        item["cn_impact"] = html.xpath("//td[text()='影响产品']/following-sibling::td[1]/text()")
        if item["cn_impact"]:
            item["cn_impact"] = "   ;   ".join([i.strip() for i in item["cn_impact"]])
        else:
            item["cn_impact"] = 'Null'
        # 获取漏洞描述
        item["cn_describe"] = html.xpath("//td[text()='漏洞描述']/following-sibling::td[1]//text()")
        if item["cn_describe"]:
            item["cn_describe"] = "".join([i.strip() for i in item["cn_describe"]]).replace("\u200b", "")
        else:
            item["cn_describe"] = 'Null'
        # 获取漏洞的参考链接
        item["cn_reference"] = html.xpath("//td[text()='参考链接']/following-sibling::td[1]/a/@href")
        if item["cn_reference"]:
            item["cn_reference"] = item["cn_reference"][0].replace('\r','')
        else:
            item["cn_reference"] = 'Null'
        # 获取漏洞的解决方案
        item["cn_solution"] = html.xpath("//td[text()='漏洞解决方案']/following-sibling::td[1]//text()")
        if item["cn_solution"]:
            item["cn_solution"] = "".join([i.strip() for i in item["cn_solution"]])
        else:
            item["cn_solution"] = 'Null'
        # 获取漏洞厂商补丁
        item["cn_patch"] = html.xpath("//td[text()='厂商补丁']/following-sibling::td[1]/a")
        if item["cn_patch"]:
            for i in item["cn_patch"]:
                list = []
                list.append(i.xpath("./text()")[0])
                list.append("http://www.cnvd.org.cn" + i.xpath("./@href")[0])
                item["cn_patch"] = list[0] + ':' + list[1]
        else:
            item["cn_patch"] = 'Null'
        # item = item.encode('utf-8') （）此处不用在进行解码处理了
        print(item)
        # 保存数据到csv
        self.save_data(item)

    def convertstringtodate(self, stringtime):
        "把字符串类型转换为date类型"
        #  把数据里的时间格式替换成数据库需要的格式。日期格式，便于后期提取数据，
        if stringtime[0:2] == "20":
            year = stringtime[0:4]
            month = stringtime[4:6]
            day = stringtime[6:8]
            if day == "":
                day = "01"
            begintime = date(int(year), int(month), int(day))
            return begintime
        else:
            year = "20" + stringtime[0:2]
            month = stringtime[2:4]
            day = stringtime[4:6]

            begintime = date(int(year), int(month), int(day))
            return begintime

    def save_data(self, item):
        # 数据保存进csv，此处可以打开，存txt类似
        # with open("./cnvd.csv", "a") as f:
        #     writer = csv.writer(f, codecs.BOM_UTF8)
        #     c = []
        #     for i in item.values():
        #         c.append(i)
        #     writer.writerow(c)

        # 数据保存进数据库mysql，链接数据库，注意port是int型，不是str，所以不要用引号，此处自行根据个人的账户和密码进行修改

        conn = pymysql.connect(
            user='root',
            password='mysql',
            host='127.0.0.1',
            port=3306,
            database='jd_1',
            use_unicode=True,
            charset="utf8"
        )
        # 获取游标
        cursor = conn.cursor()
        # 插入数据，注意看有变量的时候格式


        cursor.execute(
            """INSERT INTO cnvd_1(cn_title,pub_date,hazard_level,cn_impact,cn_describe,cn_reference,cn_solution,cn_patch) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (item["cn_title"], item["pub_date"], item["hazard_level"], item["cn_impact"], item["cn_describe"],
             item["cn_reference"], item["cn_solution"], item["cn_patch"]))
        # 提交
        conn.commit()
        # 关闭连接
        cursor.close()
    # 此处为从别的地方弄过来的存数据库的参考代码（可以忽略）
    # self.cursor.execute(
    #     '''insert into
    #         python_xiangche_hefei_hangzhou_copy(building_id, pic_label, oss_urls, commit_time)
    #         values (%s,'1',%s, %s)''',
    #     (
    #         pj,
    #         item['images_url'],
    #         time_now
    #     )
    # )
    # self.connect.commit()

    def run(self):
        # 主要运行函数
        next_url = self.start_url
        while next_url:
            time.sleep(random.randint(1, 2))
            print(next_url)
            html = self.parse(next_url)
            next_url = self.get_list_url(html)


if __name__ == "__main__":
    a = Cnvdspider()
    pool = Threadpool(2)  # 本来想弄个多线程的，没用的上，懒得改了，怕被封IP ，还是算了。。。
    a.run()
    # pool.map(a.run(),self.parse())
    pool.close()
    pool.join()
