#!/usr/bin/env python
# coding: utf-8

# In[ ]:


'''Adapted from Phistank for phishfry. This is the second portion once the original is built as a predictor.'''

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function #enforces python 3 syntax
from selenium import webdriver, common
from selenium.common.exceptions import TimeoutException
from bs4 import BeautifulSoup
import os
import pandas as pd
from urllib.request import urlopen
from urllib.error import HTTPError, URLError
from googlesearch import search

class isPhish:
    
    def __init__(self, url):
    
        self.url = url
        
        # dictionary that holds the score for this URL on all tests
        self.phishScore = {
            'index': 0,
            'phishtank': 0,
            'google': 0,
            'openfish':0,
            'iframe':0,
        }
    
   
    # Pulls phishtank local database for lookup without limits. May return limited results in lookups.
    phishreq = 'http://data.phishtank.com/data/aefb2ca09d15cc83009f3c2892d8da303da24ad0008c516b501a30d092da9e77/online-valid.csv'
    phishtank = pd.read_csv(phishreq)
    global phishlist
    phishlist = []
    for item in phishtank:
        phishlist.append(item)


    # Pulls current openfish list for local lookup.

    content = urlopen('https://openphish.com/feed.txt')
    global openlist
    openlist = []
    data = content.read()
    newData = data.decode()
    with open('test.txt','w+') as op:
        op.write(newData)
        for items in op:
            print(type(items))
            openlist.append(items)
    os.remove('test.txt')
        
    
    # Store html for use in the code using selenium.
    def getHTML(self):
        global page_html
        try:
            chrome = webdriver.Chrome()
            chrome.get(self.url)
        except TimeoutException as timeout:
            print("Connection timed out.")
        else:
            page_html = BeautifulSoup(chrome.page_source, features='lxml')
            chrome.quit()
        return page_html

    def indexChecker(self):
        '''This index checker is using a tool on the web that already works. Previous codes were deemed 
        inapprpriate by Google, and therefore violated user agreements. This method is slow as it uses selenium, 
        however it works and can help identify phishing sites. In this project, this will be part of the secondary
        once a site was deemed phishing.'''

        retVal = 0

        # Using Chrome to access web
        driver = webdriver.Chrome()
        # Open the website
        driver.get('https://indexchecking.com/')
        try:
            find_urls = driver.find_element_by_name('f_urls')
            find_urls.clear()
            find_urls.send_keys(self.url)
            button = driver.find_element_by_class_name('btn')
            button.click()
            soup = BeautifulSoup(driver.page_source)
            if soup.body.findAll(text='Indexed'):
                #print('ok')
                retVal = 1
            else:
                #print('not ok')
                retVal = -1

        except:
            print("timedout....")
            retVal = 0


        driver.quit()
        self.phishScore['index'] = retVal
        return retVal

    
    
    def googleSearch(self):
        '''Searches google to find results. If results less than ten, google may not have proper
        index of site. Probably deem suspicious.'''
        
        retVal = 0
        url = self.url
        count = 0
        try:
            for item in search(url, tld='co.in', pause=5):
                count += 1
            if count < 10:
                retVal = -1
            else:
                retVal = 1
        except:
            print('Unknown Error')
            retVal = 0
        self.phishScore['google'] = retVal
        return retVal
    
    def Phishtank(self, phishlist):
        '''Checks if url is reported to phishtank.com'''
        retVal = 0
        url = self.url
        if url in phishlist:
            retVal = -1
        else:
            retVal = 1
        self.phishScore['phishtank'] = retVal
        return retVal   

    def Openfish(self, openlist):
        '''Checks if url is reported to openfish.com'''
        retVal = 0
        url = self.url
        if url in openlist:
            retVal = -1
        else:
            retVal = 1
        self.phishScore['openfish'] = retVal
        return retVal   
        
    def iFrame(self, page_html):
        '''Checks for a type of cross-scripting. May be outdated, but still in use.'''
        retVal = 0
        url = self.url
        links = []

        answer = page_html.find_all('iframe')
        if answer != []:
            for item in page_html.find_all('iframe'):
                link = item.get('src')
                links.append(link)
                for item in links:
                    if re.match(item, url):
                        retVal = 1
                    else: 
                        retVal = -1
        else:
            retVal = 1


        self.phishScore['iframe'] = retVal
        return retVal



def PhishyOrNo(url):

    ip = isPhish(url)



    ip.getHTML()
    ip.indexChecker()
    ip.googleSearch()
    ip.Openfish(openlist)
    ip.Phishtank(phishlist)
    ip.iFrame(page_html)
    
    print(ip.phishScore)
    return ip.phishScore
