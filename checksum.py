
def read_tcp_addrs(file):
  try:
    with open("tcp_data/tcp_addrs_" + str(file) + ".txt","r") as f:
      return f.read().split()
  except:
    return "File doesn't exist"

def convert_ip_to_bytestring(ip):
  split_numbers = ip.split(".")
  bytestring = b''
  for num in split_numbers:
    byte = int(num).to_bytes(1, 'big')
    bytestring = bytestring + byte
  return bytestring 

def read_tcp_data(file):
  try:
    with open("tcp_data/tcp_data_" + str(file) + ".dat", "rb") as f:
        return f.read()
  except:
    return "File doesn't exist"

def tcp_data_length(data):
    return len(data)

def gen_ip_pseudo_header(source_addr, destination_addr, tcp_length):
    zero = b'\x00'
    ptcl = b'\x06'
    pseudo_header = source_addr + destination_addr + zero + ptcl + tcp_length.to_bytes(2, byteorder ='big')
    return pseudo_header

def get_checksum(data):
    return int.from_bytes(data[16:18], byteorder='big')

def gen_zero_checksum(data):
    tcp_zero_cksum = data[:16] + b'\x00\x00' + data[18:]
    if len(tcp_zero_cksum) % 2 == 1:
        tcp_zero_cksum += b'\x00'
    return tcp_zero_cksum

def calculate_checksum(pseudo_header, tcp_data):
    data = pseudo_header + tcp_data
    offset = 0
    total = 0
    while offset < len(data):
        word = int.from_bytes(data[offset:offset + 2], "big")
        total += word
        total = (total & 0xffff) + (total >> 16)
        offset += 2
    return (~total) & 0xffff

for i in range(10):
    source, destination = read_tcp_addrs(i)
    tcp_data = read_tcp_data(i)
    checksum = get_checksum(tcp_data)
    length = tcp_data_length(tcp_data)
    source_ip = convert_ip_to_bytestring(source)
    destination_ip = convert_ip_to_bytestring(destination)
    pseudo_header = gen_ip_pseudo_header(source_ip, destination_ip, length)
    zero_checksum = gen_zero_checksum(tcp_data)
    calc_checksum = calculate_checksum(pseudo_header, zero_checksum)
    if calc_checksum == checksum:
        print('PASS')
    else:
        print('FAIL')
