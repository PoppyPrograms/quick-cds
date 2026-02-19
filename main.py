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
raw_sock.settimeout(2) # bastard
sock = ssl_context.wrap_socket(raw_sock, server_side=True)

def get_ok_packet():
	return bytes([0xff, 0x02, 0x00, 0x00]) + b"OK"

def get_error_packet():
	return bytes([0xfe, 0x04, 0x00, 0x00]) + b"ERR\x00"

def get_response_packet(value):
	l = len(value)
	return bytes([0xff, l & 0xff, (l >> 8) & 0xff, 0x01]) + value

def safe_open(file, mode):
	try:
		return open(file, mode)
	except:
		return False

def handle_file_request(b, conn):
	size = b[1] | (b[2] << 8)
	if (size != 16):
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
		value = b[4 + size:]
		f.write(value)
		packet = get_ok_packet()
	conn.sendall(packet)

def handle_request(b, conn):
	if (b[0] == 0x00):
		return handle_file_request(b, conn)
	elif (b[0] == 0x80):
		global running
		running = 0
		conn.sendall(get_ok_packet())

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
	while True:
		try:
			p = sock.recv(4096, socket.MSG_DONTWAIT)
			if p == b"":
				break
			packet = packet + p
		except:
			return packet # done
	return packet

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
		b = conn.recv(4096)
		b = recv_all(b, conn)
		if (len(b) < 20):
			conn.sendall(get_error_packet())
		else:
			token = b[:16]
			packet = b[16:]
			if token != env.TOKEN:
				raise Exception("whatever")
			handle_request(packet, conn)
	except:
		conn.sendall(get_error_packet())
		pass
	try:
		conn.shutdown(socket.SHUT_RDWR)
		conn.close()
	except:
		pass # we don't care if it's allready closed :shrug:
