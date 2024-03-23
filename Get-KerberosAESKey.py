import argparse,binascii,hashlib
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--username", help="Username of the user. Used to create the salt")
parser.add_argument("-p", "--password", help="Plain text password of the user. Used to generate AES key")
parser.add_argument("-d", "--domain", help="Domain name. Used to create the salt")
parser.add_argument("-i", "--iteration", help="Iterations. By default it is 4096")

args = parser.parse_args()

if not args.username or not args.domain or not args.password:
    print("[-] Missing arguments... try -h or --help to see full argument list")
    exit()
print(bcolors.BOLD + "\n\033[95m[i]\033[0m All parameters are case sensitive!\n" + bcolors.ENDC)

def pbkdf2(password, salt, iterations, key_length):
    return hashlib.pbkdf2_hmac('sha1', password, salt, iterations, key_length)

AES256_constant = b"\x6B\x65\x72\x62\x65\x72\x6F\x73\x7B\x9B\x5B\x2B\x93\x13\x2B\x93\x5C\x9B\xDC\xDA\xD9\x5C\x98\x99\xC4\xCA\xE4\xDE\xE6\xD6\xCA\xE4"
IV = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
salt = (args.domain + args.username)
if args.iteration:
    iteration = args.iteration
else:
    iteration = 4096
    
derived_key = pbkdf2(args.password.encode(), salt.encode(), iteration, 32)
PBKDF2_AES256_key = derived_key

PBKDF2_AES256_key_string = binascii.hexlify(PBKDF2_AES256_key).decode()

aes = AES.new(PBKDF2_AES256_key, AES.MODE_CBC, b'\x00' * 16)
aes256_key_part1 = aes.encrypt(pad(AES256_constant, AES.block_size))
# Il faut bien redef un aes pour repartir de 0
aes = AES.new(PBKDF2_AES256_key, AES.MODE_CBC, b'\x00' * 16)
aes256_key_part2 = aes.encrypt(pad(aes256_key_part1, AES.block_size))

aes256_key = aes256_key_part1[:16] + aes256_key_part2[:16]

print("AES256 Key => " + (binascii.hexlify(aes256_key)).decode())