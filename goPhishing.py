from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
import httplib2
from bs4 import BeautifulSoup, SoupStrainer
from urllib.parse import urlparse
import urllib
import requests
import csv
import os
import time
import whois
import regex
import re
import xml.etree.ElementTree
from datetime import datetime
import dateutil.parser
from io import StringIO as io
import sys
import dryscrape
from random import shuffle
import tldextract
import socket
import ipwhois
socket.setdefaulttimeout(10)


class goPhish:
    """This class takes in a url and
    retrieves data about the web page"""

    def __init__(self, url, debugging=False):

        # the URL we are testing
        self.url = url

        parsed_uri = urlparse(self.url)
        self.domain = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
        self.domainScheme = '{uri.scheme}'.format(uri=parsed_uri)

        tldObj = tldextract.extract(self.url)
        self.domainName = tldObj.domain
        self.domainSuffix = tldObj.suffix

        # whether to print debugging info
        self.debugging = debugging

        # domain name stored from whois lookup
        self.whoisDomainName = ""

        # discard site flag
        self.discardSite = False

        # dictionary that hold the score for this URL on all tests
        self.phishScore = {
            'havingIPAddress': 0,
            'urlLength': 0,
            'shorteningService': 0,
            'havingAtSymbol': 0,
            'doubleSlashRedirecting': 0,
            'prefixSuffix': 0,
            'havingSubDomain': 0,
            'sslFinalState': 0,
            'domainRegistrationLength': 0,
            'favicon': 0,
            'port': 0,
            'httpsToken': 0,
            'requestURL': 0,
            'urlOfAnchor': 0,
            'linksInTags': 0,
            'sfh': 0,
            'submittingToEmail': 0,
            'abnormalURL': 0,
            'redirect': 0,
            'onMouseOver': 0,
            'rightClick': 0,
            'popUpWindow': 0,
            'iFrame': 0,
            'ageOfDomain': 0,
            'dnsRecord': 0,
            'webTraffic': 0,
            'pageRank': 0,
            'linksPointingToPage': 0,
            'statisticalReport': 0
        }

    def havingIP(self):
        # This one is working. May be pointless.
        retVal = -1
        try:
            parsed_uri = urlparse(self.url)
            domain = '{uri.netloc}'.format(uri=parsed_uri)
            #print('This is the domain: ', domain)
            checkIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", self.url)
            if checkIP:
                retVal = 1
#             else:
#                 print('No IP in URL.')
#                 return retVal
        except:
            printFormat("exc", "havingIP", "Unknown Error")
        self.phishScore['havingIP'] = retVal
        return retVal

    def getAnchorResult(self):
        """Whether the domain of anchor is different
        from that of the website"""
        # This one is working...
        retVal = -1
        try:
            http = httplib2.Http()
            status, response = http.request(self.url)
            positiveAnchor = 0
            negativeAnchor = 0
            for link in BeautifulSoup(response, parse_only=SoupStrainer('a', features='lxml')):
                if 'href' in link:
                    tldObj = tldextract.extract(link['href'])
                    if (tldObj.domain == self.domainName and tldObj.suffix == self.domainSuffix):
                        positiveAnchor += 1
                    else:
                        negativeAnchor += 1
            ratio = negativeAnchor / (positiveAnchor + negativeAnchor)
            if ratio > 0.5:  # site is considered Phishy
                retVal = 1
            if ratio < 0.2:
                retVal = -1
        except:
            printFormat("exc", "getAnchorResult", "No Anchors were returned. Setting to Zero")
            pass
        self.phishScore['urlOfAnchor'] = retVal
        return retVal

    # Removed Google Indexing due to issues with code and Google's terms and conditions.

    def getRedirect(self):
        #  This one is now working. Identifies redirects.
        retVal = 0
        try:
            r = requests.get(self, allow_redirects=False)
            if r.status_code == 301:
                retVal = 1
            else:
                retVal = -1
        except:
            if self.debugging:
                print("exc", "getRedirect", "Could not Contact {}".format(self))

        self.phishScore['redirect'] = retVal
        return retVal

    def getLinksInTags(self):

        """Links in <Meta>, <Script> and <Link> tags  point at same domain"""
        # This one is working.
        retVal = 0

        try:
            http = httplib2.Http()
            status, response = http.request(self.url)
            metaTags = BeautifulSoup(response, 'html.parser', parse_only=SoupStrainer(['meta', 'script', 'link']))

            matchedDomains = 0
            unMatchedDomains = 0
            for tag in metaTags:

                content = ""
                if tag.has_attr('content'):
                    content += (tag['content'])
                if tag.has_attr('src'):
                    content += (tag['src'])
                if tag.has_attr('link'):
                    content += (tag['link'])
                matchObj = re.match(r'([^a-zA-Z\d]+|http[s]?://)?([a-z0-9|-]+)\.?([a-z0-9|-]+)\.([a-z0-9|-]+)', content, re.M | re.I)
                if matchObj:
                    subdomain = matchObj.group(2)
                    midDomain = matchObj.group(3)
                    topDomain = matchObj.group(4)
                    if domain.find(midDomain) != -1:  # we have a url that matches the domain of the site
                        matchedDomains += 1
                    else:
                        unMatchedDomains += 1
#             print("Matched domains = {}".format(matchedDomains))
#             print("unMatched domains = {}".format(unMatchedDomains))

            percentUnmatched = unMatchedDomains/(matchedDomains+unMatchedDomains)

            if percentUnmatched > 0.5:  # site is considered Phishy
                retVal = 1
            else:
                retVal = -1
        except httplib2.ServerNotFoundError:
                print("exc", "getLinksInTags", "Site is Down")
                pass
        except:
                printFormat("exc", "getLinksInTags", "No tags were returned. Setting to Zero")
                pass
        self.phishScore['linksInTags'] = retVal
        return retVal

    def domainRegistrationLength(self):
        # This one is now working. Completely removed initiate whoisdoc method. normal pywhois did not work;
        # utilized IPWHOIS for next effort.
        retVal = 0
        try:
            parsed_uri = urlparse(self.url)
            domainURL = '{uri.netloc}'.format(uri=parsed_uri)
            ip = socket.gethostbyname(domainURL)
            ipwhodis = ipwhois.IPWhois(ip)
            results = ipwhodis.lookup_whois()
            for item in results['nets']:
                createdDate = item['updated']
            match = re.search(r'\d{4}-\d{2}-\d{2}', createdDate)
            createDate = datetime.strptime(match.group(), '%Y-%m-%d').date()
            #createDate = datetime.strftime(date, '%Y-%m-%d')
            currentDate = datetime.now().date()
            dateDiff = currentDate - createDate
            dateDiffInYears = (dateDiff.days + dateDiff.seconds/86400)/365.2425
            if dateDiffInYears <= 0.5:
                retVal = 1
            else:
                retVal = -1
        except:
            printFormat("exc", "domainRegistrationLength", "Error occured with domainRegistrationLength:{}".format(self.url))

        self.phishScore['domainRegistrationLength'] = retVal
        return retVal

    def hasAtSymbol(self):
        # This one is working.
        retVal = 0
        try:
            print('Checking for @ in url....')
            if '@' in self.url:
                retVal = -1
            else:
                print('No @ found....')
                retVal = 1
        except:
            printFormat("exc", "hasAtSymbol", "Unknown Error")
        self.phishScore['havingAtSymbol'] = retVal
        return retVal

    def hasDoubleSlash(self):
        # Not sure what this really does as it gives a positive retVal whether it has double slash or not.
        # Pull this one up in the documentation. For now, leave as is.
        retVal = 0
        try:
            if '//' in self.url:
                retVal = 1
            else:
                retVal = 1
        except:
            printFormat("exc", "hasDoubleSlash", "Unknown Error")
        self.phishScore['havingAtSymbol'] = retVal
        return retVal

    def hasNonStandardPort(self):
        '''May end up changing this just to check for port usage.'''
        retVal = 0
        try:
            parsed_uri = urllib.parse.urlparse(self.url)
            print(parsed_uri.port)
            if (parsed_uri.port == None or  parsed_uri.port == 80 or parsed_uri.port == 443):
                #print('Parsed uri.port is: ' + str(parsed_uri.port))
                retVal = -1
            else:
                retVal =1
        except:
            print("exc", "hasNonStandardPort", "Unknown Error")

        self.phishScore['port'] = retVal
        return retVal



    def hasPopUpWindow(self):
        '''Identifies tags commonly used for popups.'''
        # This one works.
        retVal = 0
        try:
            page = urllib.request.urlopen(self.url)
            soup = BeautifulSoup(page, features="lxml")
            data = soup.find('script')
            for tag in soup.findAll('script'):
                stringTag = str(tag)
                if re.search(r'.*open\(|alert\(|confirm\(|prompt\(.*', stringTag):
                    # If a tag is found, then code breaks and assures a positive. 
                    retVal = 1
                    break
                else:
                    retVal = -1
        except:
                printFormat("exc", "hasPopUpWindow", "Pop up window exception")        
        self.phishScore['popUpWindow'] = retVal
        return retVal
    
    def hasHttpsToken(self):
        """
        This method looks for https in the url 
        http://https-www-paypal-it-webapps-mpp-home.soft-hair.com/
        """
        # This one now works.
        retVal = 0
        parsed_uri = urlparse(self.url)
        #print(parsed_uri)

        if '{uri.scheme}'.format(uri=parsed_uri) == 'https':
            retVal = 1
        else:
            httpsDomain = 'https://{uri.netloc}/'.format(uri=parsed_uri)
            print(httpsDomain)
            try:
                http = httplib2.Http()
                status, response = http.request(httpsDomain)
                retVal = 1
            except:
                printFormat ("exc", "hasHttpsToken", "Unknown error")
                retVal = -1
            retVal = -1
        self.phishScore['httpsToken'] = retVal
        return retVal
    
    def serverFormHandler(self):
        """
        Server Form
        """
        # This one is nor working properly now. Was not pointing properly before equalling a false positive.
        retVal = 0
        try:
            page = urllib.request.urlopen(self.url)
            parsed_html = BeautifulSoup(page, features='lxml') 
            try:
                parseList = parsed_html.body.find('form').attrs
                for key, values in parseList.items():
                # Check to see what 'action' tag is doing.
                    if values == "" or values == None or values == "about:blank":
                        retVal = 1
                    else:
                        retVal = -1
            except:
                print('Error in attributes...')
        except:
                printFormat ("exc", "serverFormHandler", "SFH exception")
        self.phishScore['sfh'] = retVal
        return retVal
                  
    def onMouseOver(self):
        """
        This method looks for the on mouse over re-writing of links in the status bar.  
        This type of ruse has become less effective as browsers usually ignore this.
        """
        # This one is working however may be useless and outdated in usage. Will utilize until tested. 
        retVal = 0
        try:
            page = urllib.request.urlopen(self.url)
            parsed_html = BeautifulSoup(page, features='lxml') 
            parseList = parsed_html.body.find('a').attrs
            #print(parseList)
            for key, values in parseList.items():
                #print(key, values)
                if key == 'onmouseover':
                    match = re.search(r'window.status',tag['onmouseover'])
                    if match:
                        retVal = 1
                    else:
                        retVal = -1
                if key == 'href':  #matches the href=javascript tag
                    hrefMatch = re.search(r'javascript',tag['href'])
                    if hrefMatch:
                        retVal = 1
                    else:
                        retVal = -1
        except:
            print('onMouseOver ===> No connection....')
            printFormat("exc", "onMouseOver", "On mouse over exception")
        self.phishScore['onMouseOver'] = retVal
        return retVal
    
    
    def abnormalUrl(self):
        '''Fixed to use WHOIS from within Python to match parsed data from actual URL'''
        # Trying a different approach through the use of socket.
        retVal = 0
        try:
            
            parsed_uri = urlparse(self.url)
            domainURL = '{uri.netloc}'.format(uri=parsed_uri)
            ip = socket.gethostbyname(domainURL)
            try:
                domain = socket.gethostbyaddr(ip)[0]
                if not re.search(domain,self.url):
                    retVal = 1
                else:
                    retVal = -1
            except:
                retVal = -1
                print('***Invalid hostname***')
                return retVal
            
        except:
            printFormat("exc", "abnormalUrl", "Unknown Error")
        self.phishScore['abnormalUrl'] = retVal
        return retVal


    def getFavIcon(self):
        """Whether the domain use a favicon for website or not"""

        # This one is now working.
        retVal = 1
        try:
            http = httplib2.Http()
            parsed_uri = urlparse(self.url)
            domain = '{uri.netloc}'.format(uri=parsed_uri)
            status, response = http.request('http://' + domain + '/favicon.ico')
            if status['status'] == '200':
                retVal = -1
            else:
                retVal = 1
        except:
                printFormat ("exc", "getFavIcon", "Error for finding favicon")
        self.phishScore['favicon'] = retVal
        return retVal
    
    def geturlLength(self):
        """Finding length of each URL"""
        # This one is already working.
        retVal = 0
        try:
            if len(self.url) >= 75 :
                retVal = 1
            elif len(self.url) >= 54  :
                retVal = 0
            else:
                retVal = -1
        except:
            printFormat("exc", "geturlLength", "Unknown Error")

        self.phishScore['urlLength'] = retVal
        return retVal

    def getageOfDomain(self):
        """Get age of domain. If it is less than 10 years old, it returns 0"""
        # This one is working...
        retVal = 0
        try:
            parsed_uri = urlparse(self.url)
            domainURL = '{uri.netloc}'.format(uri=parsed_uri)
            ip = socket.gethostbyname(domainURL)
            ipwhodis = ipwhois.IPWhois(ip)
            results = ipwhodis.lookup_whois()
            for item in results['nets']:
                createdDate = item['created']
            createdDate = item['created']
            match = re.search(r'\d{4}-\d{2}-\d{2}', createdDate)
            createDate = datetime.strptime(match.group(), '%Y-%m-%d').date()
            #createDate = datetime.strftime(date, '%Y-%m-%d')
            currentDate = datetime.now().date()
            dateDiff = currentDate - createDate
            dateDiffInYears = (dateDiff.days + dateDiff.seconds/86400)/365.2425
            # print("diff in years: ",dateDiffInYears)
            if dateDiffInYears >= 10:
                retVal = 1
            else:
                retVal = -1
        except:
            printFormat("exc", "getageOfDomain", "Unknown Error" )
        self.phishScore['getageOfDomain'] = retVal
        return retVal

    def includePrefixSuffix(self):
        """If URL incldes '-' character, it has Prefix or Suffix  """
        # This one works. 
        retVal = 0
        try:
            if (self.url.find('-') >= 0 ) :
                retVal = 1
            else:
                retVal = -1
        except:
            printFormat ("exc", "includePrefixSuffix", "UnknownError" )

        self.phishScore['prefixSuffix'] = retVal
        return retVal
    
    def usingIPAddress(self):
        """ Checks for IP address in the URL which identifies bypassed security features."""
        # This one was completely redone and is working now.
        try:
            parsed_uri = urlparse(self.url)
            domain = '{uri.netloc}'.format(uri=parsed_uri)
            #print(domain)
            import socket
            ip = socket.gethostbyname(domain)
            #print(ip)
            if domain == ip:
                retVal = 1
            else:
                retVal = -1
        except:
            printFormat("usingIPAddress" , "Unknown Error")
        self.phishScore['usingIPAddress'] = retVal

    def usingSubDomains(self):
        """ If URL includes more than 3 dots, it is phishing web-site (except www. ) """
        # This one is now working.
        tempURL = self.url
        try:
            if tempURL.startswith('www.'):
                tempURL = tempURL[4:]
            retVal = 0
            if (tempURL.count('.') > 3 ) :
                retVal = 1
            else:
                retVal = -1
        except:
            printFormat("usingSubDomains", "Unknown error")
        self.phishScore['havingSubDomain'] = retVal
        return retVal


    def DNSRecord(self):
        """If DNS record in Whois is empty, the website might be a phishing one."""

        # Completely redone to utilize a free version of whois. This one now works.
        retVal = 0
        counter = 0
        try:
            parsed_uri = urlparse(self.url)
            domain = '{uri.netloc}'.format(uri=parsed_uri)
            # Open cmd to run whois query.
            command = 'whois ' + domain
            results = str(os.popen(command).read())
            results = results.splitlines()
            for line in results:
                if 'nserver' in line:
                    counter += 1
                if counter < 1:
                    retVal = 1
                else:
                    retVal = -1

        except:
            printFormat ("exc","DNSRecord","Unknown error")
        self.phishScore['dnsRecord'] = retVal

        return retVal

    def getAlexaRank(self):
        try:
            # This one is now working.
            retVal = 0
            result = dict()
            url = "http://www.alexa.com/siteinfo/" + self.url
            page = requests.get(url).text
            soup = BeautifulSoup(page, features="lxml")
            for span in soup.find_all('span'):
                if span.has_attr("class"):
                    if "globleRank" in span["class"]:
                        for strong in span.find_all("strong"):
                            if strong.has_attr("class"):
                                if "metrics-data" in strong["class"]:
                                    result['Global'] = strong.text.strip('\n\n').strip(' ')

            for item, value in result.items():
                if value != '-':
                    if int(value) < 10000:
                        retVal = 1

                elif value == '-':
                    reVal = -1

        except:
            # retVal = 1
            printFormat("exc", "getAlexaRank", "Unknown error")
        self.phishScore['statisticalReport'] = retVal
        return retVal
    
    def RequestURL(self):
        """whether src link to a out-domain website or not"""
        retVal = 0
        try:
            parsed_uri = urlparse(self.url)
            domain = '{uri.netloc}'.format(uri=parsed_uri)
            response = requests.get(url).text
            metaTags = BeautifulSoup(response)
            tags = metaTags.findAll(attrs={"src" : True})
            matchedDomains = 0
            unMatchedDomains = 0
            for tag in tags:
                matchObj = re.match(r'([^a-zA-Z\d]+|http[s]?://)?([a-z0-9|-]+)\.?([a-z0-9|-]+)\.([a-z0-9|-]+)',tag['src'],re.M|re.I)
                if matchObj:
                    subdomain = matchObj.group(2)
                    midDomain = matchObj.group(3)
                    topDomain = matchObj.group(4)
                    if domain.find(midDomain) != -1:  #we have a url that matches the domain of the site
                        matchedDomains += 1
                    else:
                        unMatchedDomains += 1
            if unMatchedDomains + matchedDomains > 1:
                percentUnmatched = unMatchedDomains/(matchedDomains+unMatchedDomains)
                if percentUnmatched > 0.5:  #site is considered Phishy
                    retVal = 1
                else:
                    retVal = -1
            else:
                retVal = -1
        except:
                printFormat("exc", "RequestURL", "No tags were returned.")
        self.phishScore['requestURL'] = retVal
        return retVal

def printFormat(printType,funcName , message):
    if printType == "exc":
        print( "{} - Func: {} , - Message : {}".format(printType,funcName,  message) )
    if printType == "siteName":
        print( "============={}=================".format(funcName) )
    if printType == "func":
        print( funcName )
    
def Measuringfeatures(fileName, IsClean):

    import csv
    Sites = []
    Scores = []
    newStr = ['havingIPAddress','urlLength','havingAtSymbol','doubleSlashRedirecting','prefixSuffix'
              ,'havingSubDomain','sslFinalState','domainRegistrationLength','favicon','port'
              ,'httpsToken','requestURL','urlOfAnchor','linksInTags','sfh','submittingToEmail'
              ,'abnormalURL','redirect','onMouseOver','rightClick'
              ,'popUpWindow','iFrame','ageOfDomain','dnsRecord','webTraffic'
              ,'linksPointingToPage','statisticalReport']

    with open("{}".format(fileName) ,"r") as f:
        Sites = f.read().splitlines()

    with open('{}_results.csv'.format(fileName),'w',newline='') as resultFile:
        w = csv.writer(resultFile)
        w.writerow(newStr)
    #resultFile = open('{}_results.csv'.format(fileName), 'w+')
    
        SiteCount = 0  #Keep Track of how many sites we have scanned

        print(SiteCount)
        '''Rules section'''
        for site in Sites:
            print('Sites scanned = ' + str(SiteCount))
            #Do not let it to test more than 100 sites
            #if SiteCount >= 5 :
                #break

            gPh = goPhish(site , debugging = False)
            #print ("Scanning: {}".format(site))
            try:
                http = httplib2.Http()
                status, response = http.request(site)
                SiteCount += 1
            except:
                print("Not Accessible")
                gPh.discardSite = True
                continue
            printFormat("siteName",site,"")
            gPh.url=site
            printFormat("func", "getAnchorResult", "")
            gPh.getAnchorResult()
            printFormat("func", "havingIP", "")
            gPh.havingIP()
            printFormat("func", "getAlexaRank", "")
            gPh.getAlexaRank()  #Page Rank """
            printFormat("func", "domainRegistrationLength", "")
            gPh.domainRegistrationLength() #this has a 500 query free limit
            printFormat("func", "getRedirect", "")
            gPh.getRedirect()
            printFormat("func", "getLinksInTags", "")
            gPh.getLinksInTags()
            printFormat("func", "hasAtSymbol", "")
            gPh.hasAtSymbol()
            printFormat("func", "hasNonStandardPort", "")
            gPh.hasNonStandardPort()
            printFormat("func", "hasPopUpWindow", "")
            gPh.hasPopUpWindow()
            printFormat("func", "hasHttpsToken", "")
            gPh.hasHttpsToken()
            printFormat("func", "serverFormHandler", "")
            gPh.serverFormHandler()
            printFormat("func", "onMouseOver", "")
            gPh.onMouseOver()
            printFormat("func", "abnormalUrl", "")
            gPh.abnormalUrl()
            printFormat("func", "getFavIcon", "")
            gPh.getFavIcon()
            printFormat("func", "geturlLength", "")
            gPh.geturlLength()
            printFormat("func", "getageOfDomain", "")
            gPh.getageOfDomain()
            printFormat("func", "includePrefixSuffix", "")
            gPh.includePrefixSuffix()
            printFormat("func", "usingIPAddress", "")
            gPh.usingIPAddress()
            printFormat("func", "usingSubDomains", "")
            gPh.usingSubDomains()
            printFormat("func", "DNSRecord", "")
            gPh.DNSRecord()
            printFormat("func", "RequestURL", "")
            gPh.RequestURL()


            resultFile.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n".format(
                            gPh.phishScore['havingIPAddress'],gPh.phishScore['urlLength'],gPh.phishScore['havingAtSymbol'],
                            gPh.phishScore['doubleSlashRedirecting'],gPh.phishScore['prefixSuffix'],
                            gPh.phishScore['havingSubDomain'],
                            gPh.phishScore['sslFinalState'],gPh.phishScore['domainRegistrationLength'],gPh.phishScore['favicon'],
                            gPh.phishScore['port'],gPh.phishScore['httpsToken'],gPh.phishScore['requestURL'],
                            gPh.phishScore['urlOfAnchor'],gPh.phishScore['linksInTags'],gPh.phishScore['sfh'],
                            gPh.phishScore['submittingToEmail'],gPh.phishScore['abnormalURL'],gPh.phishScore['redirect'],
                            gPh.phishScore['onMouseOver'],gPh.phishScore['rightClick'],gPh.phishScore['popUpWindow'],
                            gPh.phishScore['iFrame'],gPh.phishScore['ageOfDomain'],gPh.phishScore['dnsRecord'],
                            gPh.phishScore['webTraffic'],gPh.phishScore['linksPointingToPage'],
                            gPh.phishScore['statisticalReport'] , 
                            IsClean, site))



            # resultFile.flush()


        resultFile.close()


#if __name__=='__main__' :
    # make sure you have xvfb installed necesary for headless scraping
    #dryscrape.start_xvfb()
    # sys.argv[1] = name of file contains  , sys.argv[2] = username for XMPApi , sys.argv[3] = Password for XMLAPI , sys.argv[4] = add label for total data item. 0 : phishing, 1 : clean
#     print (sys.argv[1] ,sys.argv[2] ,sys.argv[3])
#     Measuringfeatures(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])