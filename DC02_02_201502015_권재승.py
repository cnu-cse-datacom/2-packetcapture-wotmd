import socket
import struct

## Ethernet
def parsing_ethernet_header(data):
	ethernet_header = struct.unpack("!6c6c2s", data)
	ether_dst = convert_ethernet_address(ethernet_header[0:6])
	ether_src = convert_ethernet_address(ethernet_header[6:12])
	ip_header = "0x"+ethernet_header[12].hex()

	print("========== Ethernet header ==========")
	print("Destination(Dst):", ether_dst)
	print("Source(Src):", ether_src)
	print("Type :", ip_header)

def convert_ethernet_address(data):
	ethernet_addr = list()
	for i in data:
		ethernet_addr.append(i.hex())
	ethernet_addr = ":".join(ethernet_addr)
	return ethernet_addr

## IP
def parsing_ip_header(data):
	ip_header = struct.unpack("!1b1c2s2s2s1c1c2s4s4s", data)
	ip_version = (ip_header[0] >> 4) & 0xF
	ip_length = (ip_header[0]) & 0xF
	Differentiated_Services_Codepoint = (ord(ip_header[1])>>2)&0x3f
	Explicit_Congestion_Notification= (ord(ip_header[1])&0x3)
	Total_length = int.from_bytes(ip_header[2], byteorder='big')
	Identification = int.from_bytes(ip_header[3], byteorder='big')
	flags = int.from_bytes(ip_header[4], byteorder='big')
	Flags = [
	(flags>>15)&0x1,	#Reserved
	(flags>>14)&0x1,	#not_fragments
	(flags>>13)&0x1,	#fragments
	(flags)&0x1fff		#fragment_offset
	]
	Time_to_live = ord(ip_header[5])
	Protocol = ord(ip_header[6])
	Header_checksum = "0x"+ip_header[7].hex()
	Source_ip_address = convert_ip_address(ip_header[8])
	Dest_ip_address = convert_ip_address(ip_header[9])

	print("========== ip_header ==========")
	print("ip_version:", ip_version)
	print("ip_length:", ip_length)
	print("Differentiated_Services_Codepoint:", Differentiated_Services_Codepoint)
	print("Explicit_Congestion_Notification:", Explicit_Congestion_Notification)
	print("Total_length:", Total_length)
	print("Identification:", Identification)
	print("flags:", hex(flags))
	print(">>>Reserved bit:", Flags[0])
	print(">>>not_fragments:", Flags[1])
	print(">>>fragments:", Flags[2])
	print(">>>fragment_offset:", Flags[3])
	print("Time to live:", Time_to_live)
	print("Protocol:", Protocol)
	print("Header_checksum:", Header_checksum)
	print("Source_ip_address:", Source_ip_address)
	print("Dest_ip_address:", Dest_ip_address)
	
	return Protocol

def convert_ip_address(data):
	ip_addr = list()
	for i in data:
		ip_addr.append(str(i))
	ip_addr = ".".join(ip_addr)
	return ip_addr
	
## TCP
def parsing_tcp_header(data):
	tcp_header = struct.unpack("!2s2s4s4s2s2s2s2s", data)
	src_port = int.from_bytes(tcp_header[0], byteorder='big')
	dec_port = int.from_bytes(tcp_header[1], byteorder='big')
	seq_num = int.from_bytes(tcp_header[2], byteorder='big')	# wireshark와 계산법이 다름
	ack_num = int.from_bytes(tcp_header[3], byteorder='big')
	flags = int(tcp_header[4].hex(),16)
	header_len = (flags >> 12) & 0xF
	Flags = [
	(flags >> 9)&0x7,	#reserved
	(flags >> 8)&0x1,	#nonce
	(flags >> 7)&0x1,	#cwr
	(flags >> 6)&0x1,	#ECN-Echo
	(flags >> 5)&0x1,	#urgent
	(flags >> 4)&0x1,	#ack
	(flags >> 3)&0x1,	#push
	(flags >> 2)&0x1,	#reset
	(flags >> 1)&0x1,	#syn
	(flags)&0x1,		#fin
	]
	window_size_value = int.from_bytes(tcp_header[5], byteorder='big')
	checksum = "0x"+tcp_header[6].hex()
	urgent_pointer = int.from_bytes(tcp_header[7], byteorder='big')
	
	print("========== tcp_header ==========")
	print("src_port:", src_port)
	print("dec_port:", dec_port)
	print("seq_num:", seq_num)
	print("ack_num:", ack_num)
	print("header_len:", header_len)
	print("flags:", flags)
	print(">>>reserved:", Flags[0])
	print(">>>nonce:", Flags[1])
	print(">>>cwr:", Flags[2])
	print(">>>ECN-Echo:", Flags[3])
	print(">>>urgent:", Flags[4])
	print(">>>ack:", Flags[5])
	print(">>>push:", Flags[6])
	print(">>>reset:", Flags[7])
	print(">>>syn:", Flags[8])
	print(">>>fin:", Flags[9])
	print("window_size_value:", window_size_value)
	print("checksum:", checksum)
	print("urgent_pointer:", urgent_pointer)
	
## UDP
def parsing_udp_header(data):
	udp_header = struct.unpack("!2s2s2s2s", data)
	src_port = int.from_bytes(udp_header[0], byteorder='big')
	dec_port = int.from_bytes(udp_header[1], byteorder='big')
	leng = int.from_bytes(udp_header[2], byteorder='big')
	checksum = "0x"+udp_header[3].hex()

	print("========== udp_header ==========")
	print("src_port:", src_port)
	print("dec_port:", dec_port)
	print("leng:", leng)
	print("header checksum:", checksum)


	
def main():
	recv_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

	print("<<<<<<<< Packet Capture Start >>>>>>>>>>>>")
	while True:
		data = recv_socket.recvfrom(20000)
		parsing_ethernet_header(data[0][0:14])
		protocol = parsing_ip_header(data[0][14:34])
		
		
		if(protocol==6):	# protocol : TCP
			parsing_tcp_header(data[0][34:54])
		elif(protocol==17):	# protocol : UDP
			parsing_udp_header(data[0][34:42])
			
def get_protocol(data):
	ip_header = struct.unpack("!1b1c2s2s2s1c1c2s4s4s", data)
	Protocol = ord(ip_header[6])
	return Protocol
			
def test():
	recv_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
	print("<<<<<<<< Packet Capture Start >>>>>>>>>>>>")
	
	while True:
		data = recv_socket.recvfrom(20000)
		
		protocol = get_protocol(data[0][14:34])
		if(protocol==6):	# protocol : TCP
			data = recv_socket.recvfrom(20000)
			parsing_ethernet_header(data[0][0:14])
			parsing_ip_header(data[0][14:34])
			parsing_tcp_header(data[0][34:54])
			break
	
	while True:
		data = recv_socket.recvfrom(20000)
		
		protocol = get_protocol(data[0][14:34])
		if(protocol==17):	# protocol : TCP
			data = recv_socket.recvfrom(20000)
			parsing_ethernet_header(data[0][0:14])
			parsing_ip_header(data[0][14:34])
			parsing_udp_header(data[0][34:42])
			break



if __name__ == '__main__':
	main()
	#test()
