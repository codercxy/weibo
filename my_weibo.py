# -*- coding: utf-8 -*-
from weibo import APIClient
from weibo import APIError
import urllib,urllib2
import cookielib
import requests
import binascii
import rsa
import base64
import re
import json
import codecs
import os
import time
import random
import yaml
import threading
import Queue
import datetime
from dateutil.parser import parse
#from http_helper import*
#设置参数
APP_KEY = '1368101505'
APP_SECRET = 'de17afd396b47759ebb91ccbdc88d914'
CALLBACK_URL = 'https://api.weibo.com/oauth2/default.html'
AUTH_URL = 'https://api.weibo.com/oauth2/authorize'

client = APIClient(app_key=APP_KEY, app_secret=APP_SECRET, redirect_uri=CALLBACK_URL)
PUBKEY = ''

file_out = ''
if not os.path.exists('result_tw.csv'):
    file_out = open('result_tw.csv','w')
    file_out.write(codecs.BOM_UTF8)
    file_out.write("time,weibo\n")
      
else:
    file_out = open('result_tw.csv','a')
    file_out.write(codecs.BOM_UTF8)
    
class MyThread(threading.Thread):
    def __init__(self, queue,lat,longt,startTime,endTime):
        threading.Thread.__init__(self)
        self.queue = queue
        self.lat = lat
        self.longt = longt
        self.startTime = startTime
        self.endTime = endTime
    def run(self):
        GetText(self.queue, self.lat, self.longt, self.startTime, self.endTime)

 
def SetPara(code):
    
#    url = client.get_authorize_url()
    #GetCode(url)
    #webbrowser.open_new(url)
    r= client.request_access_token(code)

    access_token = r.access_token #sina返回的token
    expires_in = r.expires_in #token过期的时间

    client.set_access_token(access_token, expires_in)
    return client

def GetText(queue,lat,longt,startTime,endTime):
    #南京经纬度(32.05，118.77)
    startTime = getTimeStamp(startTime)
    endTime = getTimeStamp(endTime)
    #获取到的微博数量 total_number
#    try:
#        print client.place.nearby_timeline.get(lat=lat, long=long, count=50,range=11132,starttime=startTime,
#                                         endtime=endTime)['total_number']
#    except:
#        print "total_number timeout error"
    
    #分页获取
    pagenum=1
    #输出的微博数量 count_text
    count_text=0
    #获取最后一个data数据
    lastData = ""
    while(True):
        try:
            data=client.place.nearby_timeline.get(page=pagenum,lat=lat, long=longt, count=50,range=11132,starttime=startTime,
                                                endtime=endTime)['statuses']
        except TypeError:
            try:
                data=client.place.nearby_timeline.get(page=pagenum,lat=lat, long=longt, count=50,range=11132,starttime=startTime,
                                                    endtime=endTime)
            except APIError:
                setLoginPara()
                continue
            except Exception, e:
                print "data2 exception"
                print e
        except APIError:
            setLoginPara()
            continue
        except Exception, e:
            print "data1 exception"
            print e
            continue
        if data:
            lastData = data
            pagenum+=1
            #print pagenum
#            print(len(data))
            for i in range(len(data)):

                try:
                    #print data[i]['text']
                    count_text+=1
#                    print(data[i]['text'].encode('utf-8'))
#                    print(data[i]['created_at'])
#                    file_out.write(data[i]['created_at'].encode('utf-8')+","+data[i]['text'].encode('utf-8')+"\n")
                    queue.put(data[i])
#                    fo = open(result_path,"a")
#                    fo.write(data[i]['text'].encode('utf-8'))
#                    fo.write("\n\n")
#                    fo.close
                except KeyError:
#                    print data.get(i)
                    continue
        else:
#            print "changed endTime"
            index = len(lastData)-1
            while(True):
                if index < 0:
                    break
                try:             
                    endTime = getTimeStamp(str(lastData[index]['created_at']))
#                    endTime = int(time.mktime(parse(lastData[index]['created_at']).timetuple()))
                    pagenum=1
#                    setLoginPara()
                    break
                except Exception, e:
                    print e
                    print lastData[index]['created_at']
                    index = index - 1
                    continue
            if (endTime < startTime):
                break
#            while(True):
#                
#                try:
#                    print "changed endTime"
#                    endTime = numpy.int64(time.mktime(parse(lastData[index]['created_at']).timetuple()))
#                    
#                    print endTime                    
#                    print type(endTime)
#                    break
#                except KeyError:
#                    index = index - 1                    
#                    continue
#            
#            break
    
#    print count_text
#    lock.release()
#    thread.exit_thread()  
def get_prelogin_status(username):
    prelogin_url = 'http://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su=' + get_user(username) + \
     '&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.11)';
    data = urllib2.urlopen(prelogin_url).read()
    p = re.compile('\((.*)\)')
    
    try:
        json_data = p.search(data).group(1)
        data = json.loads(json_data)
        
        servertime = str(data['servertime'])
        pubkey = str(data['pubkey'])
        nonce = data['nonce']
        rsakv = data['rsakv']
        showpin = data['showpin']
        pcid = data['pcid']

        return servertime, nonce, rsakv, pubkey, showpin, pcid
    except:
        print 'Getting prelogin status met error!'
        return None
def get_code(username, pwd, cookie_file):
    ticket = get_ticket(username, pwd, cookie_file)
    fields={  
    'action': 'login',  
    'display': 'default',  
    'withOfficalFlag': '0',  
    'quick_auth': 'null',  
    'withOfficalAccount': '',  
    'scope': '',  
    'ticket': ticket,  
    'isLoginSina': '',  
    'response_type': 'code',  
    'regCallback': 'https://api.weibo.com/2/oauth2/authorize?client_id='+APP_KEY+'&response_type=code&display=default&redirect_uri='+CALLBACK_URL+'&from=&with_cookie=',  
    'redirect_uri':CALLBACK_URL,  
    'client_id':APP_KEY,  
    'appkey62': '52laFx',  
    'state': '',  
    'verifyToken': 'null',  
    'from': '',  
    'switchLogin':'0',  
    'userId':'1792796252',  
    'passwd':'chy123569'  
    }  
    headers = {  
    "User-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0",  
           "Referer": 'https://api.weibo.com/oauth2/default.html',  
           "Content-Type": "application/x-www-form-urlencoded"}  
    post_url='https://api.weibo.com/oauth2/authorize'  
    get_code_url=requests.post(post_url,data=fields,headers=headers)
    code=get_code_url.url[47:]
    return code
def verify_code(pcid):
    url = 'http://login.sina.com.cn/cgi/pin.php?r={randint}&s=0&p={pcid}'.format(  
        randint=int(random.random() * 1e8), pcid=pcid)  
    filename = 'pin.png'  
    if os.path.isfile(filename):  
        os.remove(filename)  
   
    urllib.urlretrieve(url, filename)  
    if os.path.isfile(filename):  # get verify code successfully  
        #  display the code and require to input  
        from PIL import Image
#        import subprocess  

#        proc = subprocess.Popen(['display', filename], shell=True)
        im = Image.open(filename)
        im.show()
#        proc.stdout.read().decode('gbk')
        code = raw_input('请输入验证码:'.decode('utf-8').encode('gbk'))
        os.remove(filename)  
#        proc.kill()  
        return dict(pcid=pcid, door=code)  
    else:  
        return dict()
def get_ticket(username,pwd,cookie_file):
    login_data = {
        'entry': 'openapi',
        'gateway': '1',
        'from': '',
        'savestate': '0',
        'userticket': '1',
        'pagerefer':'',
        'ct':'1800',
        's':'1',
        'vsnf': '1',
        'vsnval':'',
        'door':'',
        'appkey':'',
        'su': '',
        'service': 'miniblog',
        'servertime': '',
        'nonce': '',
        'pwencode': 'rsa2',
        'rsakv': '1330428213',
        'sp': '',
        'sr':'1920*1080',
        'encoding': 'UTF-8',
        'cdult':'2',
        'domain':'weibo.com',
        'prelt': '2140', 
        'returntype': 'TEXT'
        }

    cookie_jar2     = cookielib.LWPCookieJar()
    cookie_support2 = urllib2.HTTPCookieProcessor(cookie_jar2)
    opener2         = urllib2.build_opener(cookie_support2, urllib2.HTTPHandler)
    urllib2.install_opener(opener2)
    #login_url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.11)'
    login_url = 'https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.15)&_=1450667802929'
    try:
        servertime, nonce, rsakv, pubkey, showpin, pcid = get_prelogin_status(username)
    except:
        return
    #Fill POST data
#    print 'starting to set login_data'
    login_data['servertime'] = servertime
    login_data['nonce'] = nonce
    login_data['su'] = get_user(username)
    login_data['sp'] = get_pwd_rsa(pwd, servertime, nonce, pubkey)
    login_data['rsakv'] = rsakv
    if showpin == 1:
        login_data.update(verify_code(pcid))
    login_data = urllib.urlencode(login_data)
    http_headers = {'User-Agent':'Mozilla/5.0 (X11; Linux i686; rv:8.0) Gecko/20100101 Firefox/8.0'}
    req_login  = urllib2.Request(
        url = login_url,
        data = login_data,
        headers = http_headers
    )
    result = urllib2.urlopen(req_login)
    text = result.read()
    text_data = json.loads(text)
    try:
        
        ticket = text_data['ticket']
#        print "ticket success!"
    except KeyError:
        print "ticket Error!"
        print text_data['reason'].encode('utf-8')
    
    return ticket
    
def get_pwd_rsa(pwd, servertime, nonce, pubkey):
    #n, n parameter of RSA public key, which is published by WEIBO.COM
    #hardcoded here but you can also find it from values return from prelogin status above
#    weibo_rsa_n = 'EB2A38568661887FA180BDDB5CABD5F21C7BFD59C090CB2D245A87AC253062882729293E5506350508E7F9AA3BB77F4333231490F915F6D63C55FE2F08A49B353F444AD3993CACC02DB784ABBB8E42A9B1BBFFFB38BE18D78E87A0E41B9B8F73A928EE0CCEE1F6739884B9777E4FE9E88A1BBE495927AC4A799B3181D6442443'
    weibo_rsa_n = pubkey
    #e, exponent parameter of RSA public key, WEIBO uses 0x10001, which is 65537 in Decimal
    weibo_rsa_e = 65537
    message = str(servertime) + '\t' + str(nonce) + '\n' + str(pwd)
    
    #construct WEIBO RSA Publickey using n and e above, note that n is a hex string
    key = rsa.PublicKey(int(weibo_rsa_n, 16), weibo_rsa_e)
    
    #get encrypted password
    encropy_pwd = rsa.encrypt(message, key)
    #trun back encrypted password binaries to hex string
    return binascii.b2a_hex(encropy_pwd)

def getTimeStamp(timeStr):
    timeArray = time.strptime(timeStr, "%Y-%m-%d %H:%M:%S")
    timeStamp = int(time.mktime(timeArray))
    return timeStamp
    
def get_user(username):
    username_ = urllib.quote(username)
    username = base64.encodestring(username_)[:-1]
    return username

def setLoginPara():
    username = '13770509171'
    pwd = 'chy123569'
    cookie_file = 'weibo_login_cookies.dat'
    code = get_code(username, pwd, cookie_file)
    SetPara(code)

class DataThread(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue
    def run(self):
        saveToExcel(self.queue)
def saveToExcel(queue):
    goon = True
    while goon:
        print "queueNUm"+str(queue.qsize())
        try:
            record = queue.get(block=True, timeout=120)
            if record and ('geo' in record) and record['geo'] and ('coordinates' in record['geo']):
                record['geo']['coordinates'] = record['geo']['coordinates'][::-1]
                record['created_at'] = formatTime(record['created_at'])
                try:
                    
                    print record['created_at']
                    file_out.write(str(record['created_at']).encode('utf-8')+","+record['text'].encode('utf-8')+"\n")
                    print "write success"
                except Exception, e:
                    print e
                    pass
            else:
                time.sleep(3)
        except Exception, e:
            goon = False
            
def formatTime(starttime):
    return datetime.datetime.fromtimestamp(time.mktime(time.strptime(starttime, '%a %b %d %H:%M:%S +0800 %Y')))
    
config = open('config.yaml')
params = yaml.load(config)
config.close()
points = params['points']
starttime = params['starttime']
endtime = params['endtime']
threadNum = params['threadNum']

if __name__ == "__main__":
    setLoginPara()
    #南京经纬度（32.05 118.77）
#    lat=32.05
#    long=118.77
#    locks = []
#    for i in range(threadNum):
#        lock = thread.allocate_lock()
#        lock.acquire()
#        locks.append(lock)
    
    print starttime
    print endtime
    queue = Queue.Queue(maxsize = 0)
    threads = []
#    lock_index = 0
    for point in points:
        try:
#            print "new thread #" + str(lock_index)
            thread = MyThread(queue, point['lat'], point['longt'], starttime, endtime)
            thread.start()
            threads.append(thread)
        except Exception, e:
            
            print "Error: unable to start thread at"+point['name']
            print e
            
    dts = []
    for i in range(threadNum):
        try:
            thread = DataThread(queue)
            thread.start()
            dts.append(thread)
        except Exception, e:
            print e
    
    for thread in threads:
        thread.join()
        
    for thread in dts:
        thread.join()
#        lock_index += 1
#        GetText(point['lat'], point['long'], starttime, endtime)
    
#    for lock in locks:
#        while lock.locked():
#            pass
#    print "start saving to Excel!"
#    saveToExcel(queue)

    
#    queue.join()
    #设置起止时间
#    startTime='2016-10-01 00:00:00'
#    endTime='2016-11-04 00:00:00'
#    GetText(lat,long,startTime, endTime)
