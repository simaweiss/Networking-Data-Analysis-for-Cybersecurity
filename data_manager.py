
from utilities import *


class DataManager:
    #data directory path
    destination_path = './Data'
    # zip path
    zip_path = 'Data/2019-08-13-MedusaHTTP-malware-traffic.pcap.zip'
    # password for zip
    str_pwd = 'infected'
    database_path = 'Data/GeoLite2-city_20201229/GeoLite2-city.mmdb'
    csv_path = 'Data/data.csv'
    utilities = Utilities()

    def requestedStreamsInCsv(self):
        file_path_pcap = self.utilities.extract_file_from_zip(self.zip_path, self.str_pwd, self.destination_path)
        packets = self.utilities.load_packets_from_pcap(file_path_pcap)
        self.utilities.unique_pcackets_from_pcap_to_csv(self.csv_path, self.database_path, packets)
