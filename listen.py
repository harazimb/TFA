import sys
import time
import hashlib
import alsaaudio
import numpy as np
import threading

HANDSHAKE_START_HZ = 19000
HANDSHAKE_END_HZ = 19000 + 512

START_HZ = 15000
STEP_HZ = 250
BITS = 4

FEC_BYTES = 4

previous_hash = 'Hello'
current_hash = str(hashlib.md5(str(previous_hash).encode('utf-8')).hexdigest())
print("I AM CURRENT HASH")
print(current_hash)
next_hash =  str(hashlib.md5(str(current_hash).encode('utf-8')).hexdigest())
print(next_hash)


def get_next_hash():
	next_call = time.time()
    	while True:
		global previous_hash, current_hash, next_hash
		previous_hash = current_hash
		current_hash = next_hash
		next_hash = str(hashlib.md5(str(current_hash).encode('utf-8')).hexdigest())
		print(next_hash)
		next_call = next_call+10
		time.sleep(next_call-time.time())
def dominant(frame_rate, chunk):
    w = np.fft.fft(chunk)
    freqs = np.fft.fftfreq(len(chunk))

    peak_coeff = np.argmax(np.abs(w))
    peak_freq = freqs[peak_coeff]
    return abs(peak_freq * frame_rate) # in Hz

def match(freq1, freq2):
    return abs(freq1 - freq2) < 20

def decode_bitchunks(chunk_bits, chunks):
    print("DECODING BITCHUNKS")
    out_bytes = []

    next_read_chunk = 0
    next_read_bit = 0

    byte = 0
    bits_left = 8
    while next_read_chunk < len(chunks):
	can_fill = chunk_bits - next_read_bit
        to_fill = min(bits_left, can_fill)
        offset = chunk_bits - next_read_bit - to_fill

        byte <<= to_fill
        shifted = chunks[next_read_chunk] & (((1 << to_fill) - 1) << offset)
        byte |= shifted >> offset;
        bits_left -= to_fill
        next_read_bit += to_fill

        if bits_left <= 0:
            out_bytes.append(byte)
            byte = 0
            bits_left = 8

        if next_read_bit >= chunk_bits:
            next_read_chunk += 1
            next_read_bit -= chunk_bits
    return out_bytes

def eliminate_dups(freqs):
	previous = freqs[0]
	new_freqs = []
	found = 1
	for freq in freqs:
		if previous-21 < freq < previous+21 and found == 1:
			found = 0
			previous = freq
		else:
			new_freqs.append(freq)
			found = 1
			previous = freq
	return new_freqs

def extract_packet(freqs):
    freqs = eliminate_dups(freqs)
    bit_chunks = [int(round((f - START_HZ) / STEP_HZ)) for f in freqs]
    bit_chunks = [c for c in bit_chunks if 0 <= c < (2 ** BITS)]
    return bytearray(decode_bitchunks(BITS, bit_chunks))

def listen_linux(frame_rate=44100, interval=0.1):
    mic = alsaaudio.PCM(alsaaudio.PCM_CAPTURE, alsaaudio.PCM_NORMAL)
    mic.setchannels(1)
    mic.setrate(44100)
    mic.setformat(alsaaudio.PCM_FORMAT_S16_LE)

    num_frames = int(round((interval / 2) * frame_rate))
    mic.setperiodsize(num_frames)

    in_packet = False
    packet = []

    print("Listening for data...")
    while True:
        l, data = mic.read()
        if not l:
            continue

        chunk = np.fromstring(data, dtype=np.int16)
        dom = dominant(frame_rate, chunk)
        if in_packet and match(dom, HANDSHAKE_END_HZ):
            byte_stream = extract_packet(packet)
	    print(str(byte_stream))
	    global previous_hash, current_hash, next_hash
	    print(previous_hash)
	    print(current_hash)
	    print(next_hash)
	    check_prev = previous_hash[-5:]
	    check_curr = current_hash[-5:]
	    check_next = next_hash[-5:]
	    print(check_prev)
	    print(check_curr)
	    print(check_next)
	    byte_stream = str(byte_stream)
	    if byte_stream == check_prev or byte_stream == check_curr or byte_stream == check_next:
		print("WE HAVE A MATCH")
	    else:
		print("YOU ARE NOT ALLOWED IN")

            packet = []
            in_packet = False
        elif in_packet:
	    print(dom)
            packet.append(dom)
        elif match(dom, HANDSHAKE_START_HZ):
            in_packet = True

if __name__ == '__main__':
	hashThread = threading.Thread(target=get_next_hash)
	hashThread.daemon = True
	hashThread.start()
	listen_linux()
