from urllib.parse import urlparse
import re
import urllib
import urllib.request
from xml.dom import minidom
import csv
import pygeoip as pygeoip
from pysafebrowsing import SafeBrowsing



opener = urllib.request.build_opener()
opener.addheaders = [('User-agent', 'Mozilla/5.0')]
print(opener)

nf = -1


def Tokenise(url):
    if url == '':
        return [0, 0, 0]
    token_word = re.split('\W+', url)
   
    no_ele = sum_len = largest = 0
    for ele in token_word:
        l = len(ele)
        sum_len += l
        if l > 0:  
            no_ele += 1
        if largest < l:
            largest = l
    try:

        return [float(sum_len) / no_ele, no_ele, largest]
    except:
        return [0, no_ele, largest]


def find_ele_with_attribute(dom, ele, attribute):
    for subelement in dom.getElementsByTagName(ele):
        if subelement.hasAttribute(attribute):
            return subelement.attributes[attribute].value
    return nf


def sitepopularity(host):
    xmlpath = 'http://data.alexa.com/data?cli=10&dat=snbamz&url=' + host
   
    try:
        xml = urllib.urlopen(xmlpath)
        dom = minidom.parse(xml)
        rank_host = find_ele_with_attribute(dom, 'REACH', 'RANK')

        rank_country = find_ele_with_attribute(dom, 'COUNTRY', 'RANK')
        return [rank_host, rank_country]

    except:
        return [nf, nf]


def Security_sensitive(tokens_words):
    sec_sen_words = ['confirm', 'account', 'banking', 'secure', 'ebayisapi', 'webscr', 'login', 'signin']
    cnt = 0
   
    for ele in sec_sen_words:
        if (ele in tokens_words):
            cnt += 1
    
    return cnt


def exe_in_url(url):
  
    if url.find('.exe') != -1:       
        return 1
  
    return 0


def Check_IPaddress(tokens_words):
    cnt = 0
    
    for ele in tokens_words:
        ele = bytes(ele,'utf-8')
        if (ele).isdigit():
            cnt += 1
        else:
            if cnt >= 4:
                return 1
            else:
                cnt = 0;
    if cnt >= 4:
        return 1
    
    return 0


def getASN(host):
    try:
        g = pygeoip.GeoIP('GeoIPASNum.dat')
        asn = int(g.org_by_name(host).split()[0][2:])
        
        return asn
    except:        
        return nf


def safebrowsing(url):
    api_key = "AIzaSyAKlIvwipJ0YWcmc2Emz9ssRegTE8V_33s"
    name = "URL_check"
    ver = "4.0"
    
    req = {}
    req["client"] = name
    req["apikey"] = api_key
    req["appver"] = ver
    req["pver"] = "3.0"
    req["url"] = url  


    try:
        s = SafeBrowsing(api_key)
        r = s.lookup_urls([url])
        print(r)
        if r[url]['malicious'] == True:
            print("Unsafe")
            return 1
        else:
            print("Safe")
            return 0

    
    except:
        return -1


def feature_extract(url_input):
    Feature = {}
    tokens_words = re.split('\W+', url_input) 
    
    print(tokens_words)
    

    obj = urlparse(url_input)
    host = obj.netloc
    path = obj.path

    Feature['URL'] = url_input

    Feature['rank_host'], Feature['rank_country'] = sitepopularity(host)

    Feature['host'] = obj.netloc
    Feature['path'] = obj.path

    Feature['Length_of_url'] = len(url_input)
    Feature['Length_of_host'] = len(host)
    Feature['No_of_dots'] = url_input.count('.')

    Feature['avg_token_length'], Feature['token_count'], Feature['largest_token'] = Tokenise(url_input)
    Feature['avg_domain_token_length'], Feature['domain_token_count'], Feature['largest_domain'] = Tokenise(host)
    Feature['avg_path_token'], Feature['path_token_count'], Feature['largest_path'] = Tokenise(path)
    
    Feature['sec_sen_word_cnt'] = Security_sensitive(tokens_words)
    Feature['IPaddress_presence'] = Check_IPaddress(tokens_words)

    print(host)
    print(getASN(host))
    Feature['exe_in_url'] = exe_in_url(url_input)
    Feature['ASNno'] = getASN(host)
    Feature['safebrowsing'] = safebrowsing(url_input)
    
    print(Feature)
    return Feature


print("feature extraction is running.......")
