#!/usr/bin/python3

import itertools
from Crypto.Util.strxor import *
import binascii
import json
import argparse
import logging

#sum of freq of all character in s
def total_freq(s):
    return sum([freq[x] for x in s if x in freq])

#return total_freq of second element in tupe of paire
def score(paire):
    return total_freq(paire[1])

#load freq from file
def load_freq(file_name):
    freq = dict()
    with open(file_name,'r') as f:
        lines = f.readlines()
        freq = zip([x for x in range(256)],map(float, lines))
    return dict(freq)

#crack single xor key
def crack_single_xor(s):
    return max([(i,strxor_c(s,i)) for i in range(256)], key=score)

def hamming_distance(x,y):
    if len(x)!=len(y):
        return 10000
    return sum([bin(x[i]^y[i]).count('1') for i in range(len(x))])

def normalizedEditDistance(x,k):
    blocks = [x[i:i+k] for i in range(0, len(x), k)][0:4]
    pairs = list(itertools.combinations(blocks,2))
    scores = [hamming_distance(p[0], p[1])/float(k) for p in pairs][0:6]
    return sum(scores) / len(scores)

def crack_repeated_xor(x,k):
    blocks = [x[i:i+k] for i in range(0, len(x), k) if i+k < len(x)]
    transposedBlocks = list(itertools.zip_longest(*blocks, fillvalue = 0))
    key = [crack_single_xor(bytes(x))[0] for x in transposedBlocks]
    return bytes(key)

def decrypt_xor(s, k):
    ans = bytearray()
    for i in range(len(s)):
        ans.append(s[i]^k[i%len(k)])
    return ans

def guest_key_length(min_len, max_len, cipher):
    print('[+] Guessing key length from {} to {} ...'.format(min_len,max_len))
    return min(range(min_len, max_len), key=lambda k: normalizedEditDistance(cipher,k))

if __name__ == '__main__':
    #Setting pairser
    parser = argparse.ArgumentParser(
        prefix_chars='-'
    )
    parser.add_argument('--in', action='store', dest = 'file_in', help='Cipher file to decrypt')
    parser.add_argument('--out', action='store', dest = 'file_out', help='Decrypt and save plaintext to file_out.')
    parser.add_argument('--freq', action='store', dest = 'file_freq', help='Frequent character file.', default = 'linux-2.2.14-int-m0.freq')
    parser.add_argument('--min', action='store', dest='min_length', help='Minimum length of key.', type=int, default=1)
    parser.add_argument('--max', action='store', dest='max_length', help='Maximum length of key.', type=int, default=51)
    args = parser.parse_args()

    #Main program
    global freq
    freq = load_freq(args.file_freq)
    #try:
    with open(args.file_in,'rb') as f:
        cipher=f.read()
        key_len = guest_key_length(args.min_length, min(len(cipher),args.max_length), cipher)
        print('[+] Detected key length: ' + str(key_len))
        key = crack_repeated_xor(cipher,key_len)
        print('[+] Found key: [' + key.decode()+']')
        plain_text = decrypt_xor(cipher,key).decode()
        if args.file_out == None:
            print('[+] Plain text:')
            print(plain_text)
        else:
            with open(args.file_out, 'w') as fout:
                fout.write(plain_text)
            print('[+] Write plaintext to [{}] success!'.format(args.file_out))

    #except Exception as e:
    #    print('[+] ERROR: '+str(e))

       
