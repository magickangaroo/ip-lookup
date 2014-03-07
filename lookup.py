__author__ = 'adz'

from cymruwhois import Client
import csv
import datetime
import os
import requests
import sys
from dns import resolver, reversename
import pygeoip

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

    addr=reversename.from_address(ip)
    responses = []
    for response in resolver.query(addr, "PTR"):
        responses.append(str(response))

    if ip in malwarelist:
        return '\n '.join(responses), "True"
    else:
        return '\n '.join(responses), "False"

def retKML(ip):
    rec = gi.record_by_name(ip)
    try:
        longitude = rec['longitude']
        latitude = rec['latitude']
        kml = (
               '<Placemark>\n'
               '<name>%s</name>\n'
               '<Point>\n'
               '<coordinates>%6f,%6f</coordinates>\n'
               '<extrude>2</extrude>\n'
               '<altitudeMode>relativeToGround</altitudeMode>\n'
               '</Point>\n'
               '</Placemark>\n'
               ) %(ip,longitude, latitude)
        return kml
    except:
        return ''

def plotIPs(iplist):
    kmlPts = ''
    for ip in iplist:
        kmlPts = kmlPts + retKML(ip)
    return kmlPts

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

    iplistwithnullsremoved = [x for x in iplist if x]

    ofile = open('results.csv', "wb")
    writer = csv.writer(ofile, delimiter='\t', quotechar='"', quoting=csv.QUOTE_ALL)

    for entry in c.lookupmany(iplistwithnullsremoved):
        iplookup = lookup(entry.ip, malwarelist)

        row = entry.ip + ", " + entry.owner + ", " + entry.asn + ", " + entry.prefix + ", " + entry.cc + ", " + \
            iplookup[0] + ", " + iplookup[1]
        writer.writerow(row)

    ofile.close()



    gi = pygeoip.GeoIP('GeoIP.dat/GeoLiteCity.dat')

    kmlheader = '<?xml version="1.0" encoding="UTF-8"?>\
    \n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'
    kmlfooter = '</Document>\n</kml>\n'


    kmldoc=kmlheader+plotIPs(iplistwithnullsremoved)+kmlfooter

    f = open('plot.kml','w')
    f.write(kmldoc)
    f.close()