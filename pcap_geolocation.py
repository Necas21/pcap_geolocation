import geoip2.database
import dpkt
import socket
import argparse
import sys
import os


# Looks up the ip_address in the Maxmind GeoLite2-City database, returns (latitude, longitude)
def get_geoip(ip_address, path_to_db):

	try:
		with geoip2.database.Reader(path_to_db) as reader:

			response = reader.city(ip_address)
			country = response.country.name
			city = response.city.name
			postal_code = response.postal.code
			longitude = response.location.longitude
			latitude = response.location.latitude

			return (latitude, longitude)

	except:
		return (None, None)


# Parses PCAP file and returns the destination IP
def parse_pcap(pcap_file):

	dest_ips = []

	with open(pcap_file, "rb") as f:
		pcap = dpkt.pcap.Reader(f)

		for (ts, buf) in pcap:
			try:
				eth = dpkt.ethernet.Ethernet(buf)
				ip = eth.data
				tcp = ip.data
				src = socket.inet_ntoa(ip.src)
				dst = socket.inet_ntoa(ip.dst)

				if (dst, tcp.dport) not in dest_ips:
					dest_ips.append((dst, tcp.dport))

			except:
				pass

	return dest_ips


# Creates a KML file based on the destination IP addresses and their geolocations
def create_kml(ip, port, lat, lon):

	green = "ff00ff00"
	red = "ff0000ff"
	# Default blue color
	color = "ffff0000"

	if port == "443":
		color = green

	elif port == "80":
		color = red

	kml = ("<Placemark>\n"
			f"<name>{ip}</name>\n"
			"<Point>\n"
			f"<coordinates>{lon},{lat}</coordinates>\n"
			"<LineStyle>"
			"<color>{color}</color>"
			"</LineStyle>"
			"</Point>\n"
			"</Placemark>\n")

	return kml


def main():

	parser = argparse.ArgumentParser()
	parser.add_argument("-p", dest="pcap_file", help="Specify the path to the PCAP file.")
	parser.add_argument("-d", dest="geo_db", help="Specify the path to the GeoIP database file.")
	parser.add_argument("-o", dest="output", help="Specify the path to the output KML file.")

	if len(sys.argv) != 7:
		parser.print_help(sys.stderr)
		sys.exit(1)

	args = parser.parse_args()
	pcap_file = args.pcap_file
	geo_db = args.geo_db
	output = args.output
	dest_ips = parse_pcap(pcap_file)

	if os.path.exists(output):
		os.remove(output)

	with open(output, "a") as kml_file:
		kml_file.write("<?xml version='1.0' encoding='UTF-8'?>\n")
		kml_file.write("<kml xmlns='http://www.opengis.net/kml/2.2'>\n")
		kml_file.write("<Document>\n")
	
		for (ip, port) in dest_ips:
			(lat, lon) = get_geoip(ip, geo_db)
			if lat != None and lon != None:
				kml = create_kml(ip, port, lat, lon)
				kml_file.write(kml)

		kml_file.write("</Document>\n")
		kml_file.write("</kml>")

	print(f"[*] KML output written to: {output}")


if __name__ == "__main__":
	main()