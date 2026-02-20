import socket
import os
import ssl
import env

HOST = "0.0.0.0"
PORT = 7345 # tootoo pls fix

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain("ssl/cert.pem", "ssl/key.pem")

raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
raw_sock.bind((HOST, PORT))
raw_sock.listen()
raw_sock.settimeout(1) # bastard
sock = ssl_context.wrap_socket(raw_sock, server_side=True)
sock.settimeout(1) # :rage:

CONTENT_HEADER_LENGTH = 8
HASH_SIZE = 16

def get_ok_packet():
	return bytes([0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) + b"OK"

def get_error_packet():
	return bytes([0xfe, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) + b"ERR\x00"

def get_response_packet(value):
	l = len(value)
	return bytes([0xff, l & 0xff, (l >> 8) & 0xff, (l >> 16) & 0xff, (l >> 24) & 0xff, (l >> 32) & 0xff, (l >> 40) & 0xff, (l >> 48) & 0xff]) + value

def decode_content_header(header):
	l = header[0] | (header[1] << 8) | (header[2] << 16) | (header[3] << 24) | (header[4] << 32) | (header[5] << 40) | (header[6] << 48) | (header[7] << 56)
	return l

def safe_open(file, mode):
	try:
		return open(file, mode)
	except:
		return False

def handle_file_request(b, conn):
	size = b[1] | (b[2] << 8)
	if (size != HASH_SIZE):
		conn.sendall(get_error_packet())
		return
	direction = b[3]
	hash = b[4:4 + size].hex()
	packet = get_error_packet()
	if (direction == 0x00): # read
		f = safe_open("data/" + hash, "rb")
		if f == False:
			conn.sendall(get_error_packet())
			return
		value = f.read()
		packet = get_response_packet(value)
	elif (direction == 0x01): # write
		f = safe_open("data/" + hash, "wb")
		if f == False:
			conn.sendall(get_error_packet())
			return
		value = b[4 + CONTENT_HEADER_LENGTH + size:]
		f.write(value)
		packet = get_ok_packet()
	conn.sendall(packet)

def validate_file_request(b):
	size = b[1] | (b[2] << 8)
	if (size != 16):
		return False
	direction = b[3]
	if (direction == 0x00): # read
		return True
	elif (direction == 0x01): # write
		content_header = b[4 + size:4 + CONTENT_HEADER_LENGTH + size]
		content_length = decode_content_header(content_header)
		packet_length = 4 + 16 + CONTENT_HEADER_LENGTH + content_length
		if (len(b) == packet_length):
			return True
		return False
	return True # sure

def handle_request(b, conn):
	if (b[0] == 0x00):
		return handle_file_request(b, conn)
	elif (b[0] == 0x80):
		global running
		running = 0
		conn.sendall(get_ok_packet())

def validate_request(b):
	if (b[0] == 0x00):
		return validate_file_request(b)
	elif (b[0] == 0x80):
		return True
	return True # uhm...???

def data_exists():
	try:
		open("data").close()
		os.remove("data")
		return False
	except IsADirectoryError:
		return True
	except:
		return False

if not data_exists():
	try:
		os.mkdir("data")
		if not data_exists():
			print("ERROR; HI. DATA DIRECTORY COULD NOT BE CREATED")
			exit(-1)
	except:
		print("ERROR; HI. DATA DIRECTORY COULD NOT BE CREATED")
		exit(-1)

def recv_all(packet: bytes, sock):
	n = packet
	while True:
		try:
			p = sock.recv(16384)
			if not p:
				return n
		except:
			return n # done
		n = n + p
	return n

def full_packet_received(b: bytes):
	if (len(b) < 20):
		return 0
	packet = b[16:]
	return validate_request(packet)

running = 1
seconds_waiting = 0
while running:
	try:
		conn, addr = sock.accept()
	except TimeoutError:
		seconds_waiting = seconds_waiting + 1
		continue
	except:
		continue
	try:
		conn.settimeout(1) # my rage knows no bounds
		b = conn.recv(16384)

		retries = 3
		while (not full_packet_received(b)) and retries > 0:
			b = recv_all(b, conn)
			retries = retries - 1

		if (not full_packet_received(b)) or retries <= 0:
			raise Exception("recv error")

		token = b[:16]
		packet = b[16:]
		if token != env.TOKEN:
			raise Exception("whatever")
		handle_request(packet, conn)
	except:
		try:
			conn.sendall(get_error_packet())
		except:
			pass
	try:
		conn.shutdown(socket.SHUT_RDWR)
		conn.close()
	except:
		pass # we don't care if it's allready closed :shrug:
