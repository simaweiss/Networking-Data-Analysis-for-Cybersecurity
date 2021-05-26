from zipfile import *
import csv
import os
import geoip2.database
from geoip2.errors import AddressNotFoundError
from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP


class Utilities:
    # extract files
    def extract_file_from_zip(self, zip_path, str_pwd, destination_path):
        with ZipFile(zip_path) as zipObj:
            zipObj.extractall(destination_path,pwd=bytes(str_pwd, 'utf-8'))
            files_list = zipObj.namelist()
            requested_file = files_list[0]
            file_path = os.path.join(destination_path, requested_file)
        return file_path


    # load packets
    def load_packets_from_pcap(self, str_Pcap):
        packets = rdpcap(str_Pcap)
        return packets

    # get country by IP
    def get_geo_ip(self,ip, reader_db):
        try:
            response = reader_db.city(ip)
            country = response.country.name

        except AddressNotFoundError:
            country = 'no geo info'
        return country

    #get unique packets HttpRequest / DNSQR , from them specified fileds and write to CSV file
    def unique_pcackets_from_pcap_to_csv(self,csv_path, db_path, packets):
        reader_db = geoip2.database.Reader(db_path)
        with open(csv_path, 'w', newline='') as csvfile:
            fieldnames = ['IP source', 'port source', 'source geo', 'IP dest', 'port dest', 'dest geo',
                          'HTTP request type']
            thewriter = csv.DictWriter(csvfile, fieldnames=fieldnames)
            thewriter.writeheader()
            for packet in packets:
                if packet.haslayer('HTTPRequest') or packet.haslayer('DNSQR'):
                    src = packet[IP].src
                    dst = packet[IP].dst
                    sport = packet.sport
                    dport = packet.dport
                    src_geo = self.get_geo_ip(src, reader_db)
                    dst_geo = self.get_geo_ip(dst, reader_db)
                    if packet.haslayer('HTTPRequest'):
                        method_type = packet[HTTPRequest].Method.decode()
                    elif packet.haslayer('DNSQR'):
                        method_type = ''
                    thewriter.writerow(
                        {'IP source': src, 'port source': sport, 'IP dest': dst,
                         'port dest': dport, 'HTTP request type': method_type, 'source geo': src_geo,
                         'dest geo': dst_geo})




