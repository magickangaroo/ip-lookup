__author__ = 'adz'
import dns.resolver
import dns.query
import dns.zone
import dns.reversename
from cymruwhois import Client
import csv
import datetime
import os
import requests
import sys

csvfilename = "malware.csv"

def getupdatedlist():

    url = "http://www.malwaredomainlist.com/mdlcsv.php"
    print "downloading CSV"

    with open(csvfilename, 'wb') as handle:
        request = requests.get(url, stream=True)
        for block in request.iter_content(1024):
            if not block:
                break
            handle.write(block)

def readcsv(csvfilename):
    print "readcsv" + csvfilename
    malwarelist=[]
    with open(csvfilename, 'rb') as f:
        reader = csv.reader(f)
        try:
            for row in reader:
                malwarelist.append(row[2])
        except IndexError:
            #skip null lines and index errs
                pass
        finally:
            f.close()
            return malwarelist

def readtextfile(txtfilename):
    text_file = open(txtfilename, "r")
    textlist = text_file.read().split('\n')
    text_file.close()
    return textlist


def lookup(ip, malwarelist):
    if ip in malwarelist:
        return "True"
    else:
        return "False"

if __name__ == "__main__":

    c=Client()

    #check for file and age, download if appropriate

    if os.path.isfile(csvfilename):
        filetimestamp = datetime.datetime.fromtimestamp(os.stat(csvfilename).st_mtime)
        delta = datetime.datetime.now() - filetimestamp

        if delta.days > 2:
            getupdatedlist()
    else:
        getupdatedlist()

    if os.path.isfile(csvfilename):
        malwarelist = readcsv(csvfilename)
    else:
        print "malware file not found!"
        sys.exit()

    if os.path.isfile("ipsofconcern.txt") is False:
        print "ip's of concern file not found"
        sys.exit()

    iplist = readtextfile("ipsofconcern.txt")
    
    for entry in c.lookupmany(iplist):
        print entry.ip + ", " + entry.owner + ", " +  entry.asn + ", " + entry.prefix + ", " + entry.cc + ", " + \
              str(dns.reversename.from_address(entry.ip)) + lookup(entry.ip)





