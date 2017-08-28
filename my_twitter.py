Twitter API

#coding: UTF-8

from twitter import Twitter
from twitter import OAuth

import xlwt
import os
import xlrd
from xlrd import open_workbook
from xlutils.copy import copy

os.chdir("C:\\Users\\57248\\DeskTop\\")


consumer_key = 'plbOgBh0N2X2WE1ZBygXoSe8m'
consumer_secret = 'nTnafQhrHRGKKKBHPHhShkemaJIcjcsIKIbqWgB3hevdPx8kJx'
access_token = '712922892791652354-5Dm8ovd0Tx1To1PcjuJ5Xf6zFsvx4hZ'
access_secret = 'Flf15x9qnRc33fBhjJrztrv6FetCHvXxns24ag1uZrFZg'

tweets       = []   #tweet数组
MAX_ATTEMPTS = 10   #最多页数，每页15条
COUNT        = 500  #最多获取twitter数量

#最大返回tweets数量：100+15*(MAX_ATTEMPTS - 1) 即当MAX值为10时，最大返回235条tweets
#如果返回tweets数量大于这个值，可以设置较大的 MAX_ATTEMPTS和 COUNT值

def search_api(query, lan, file_name):
    #设置参数
    t = Twitter(auth=OAuth(access_token, access_secret,
                           consumer_key, consumer_secret))
    next_max_id  = 0
    for i in range(0, MAX_ATTEMPTS):
        if (COUNT < len(tweets)):
            break
        if(i == 0):
            #第一页查询结果
            results = t.search.tweets(q=query, lang=lan,since_id='00000',result_type='mixed',count='100')
        else:
            #非第一页查询结果
            results = t.search.tweets(q=query, lang=lan,since_id='00000',result_type='mixed',
                                      include_entities='true',max_id=next_max_id)
        #查询结果处理
        for result in results['statuses']:
            tweet_text = result['text']
            write_to_excel(file_name, tweet_text)
            tweets.append(tweet_text)
        #获取下一页的max_id
        try:
            next_results_url_params = results['search_metadata']['next_results']

            next_max_id = next_results_url_params.split('max_id=')[1].split('&')[0]
        except:
            break
    #tweet数量
    print "tweet num:"
    print len(tweets)
def write_to_excel(file_name, text):
    try:   
        rb = open_workbook(file_name)
        sheet = rb.sheets()[0]
        row_num = sheet.nrows

        wb = copy(rb)
        ws = wb.get_sheet(0)
        ws.write(row_num,0,text)
        wb.save(file_name)
    except(IOError):
        book = xlwt.Workbook(encoding='utf-8', style_compression=0)
        sheet = book.add_sheet('tweet', cell_overwrite_ok=True)
        sheet.write(0,0,text)
        book.save(file_name)
if __name__ == "__main__":
    #搜索关键词
    query = 'obama'
    #文件名 .xls后缀
    file_name = 'tweet.xls'
    #设置语言:中文_zh, 英文_en
    lan = 'en'
    #format YYYY-MM-DD,返回这个日期前的tweet
    #until = '2016-09-01'
    search_api(query, lan, file_name)





