#!venv/bin/python
import os
import time
import sys
import argparse
import random
import xxhash
import hashlib
import select
import pathlib
import secrets
import gzip
from hashlib import sha512
from PIL import Image
from io import BytesIO
from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes


parser = argparse.ArgumentParser()

parser.add_argument('action', nargs='?')
parser.add_argument('-m', '--message')
parser.add_argument('-p', '--password')
parser.add_argument('-mt', '--method')
parser.add_argument('-if', '--image_file')
parser.add_argument('-mf', '--message_file')
parser.add_argument('-o', '--output')
# parser.add_argument("-piu", "--pipeimageupload", help="FIFO with image data")
# parser.add_argument("-pid", "--pipeimagedownload", help="FIFO with image data")
# parser.add_argument("-pmu", "--pipemessageupload", help="FIFO with message data")
# parser.add_argument("-pmd", "--pipemessagedownload", help="FIFO with message data")
# parser.add_argument("-pw", "--password", help="FIFO with message data")
# parser.add_argument("-ph", "--pipepasshash", help="FIFO with message data")

args = parser.parse_args()

class Steganography:

    @staticmethod
    def __convert_to_binary(cipher_bytes:bytes):
        return [format(x, 'b').zfill(8) for x in cipher_bytes]
    
    @staticmethod
    def __convert_to_text(binary:list[str]):
        text = ''.join([format(int(txt, 2), 'x').zfill(2) for txt in binary])
        return bytes.fromhex(text)
    
    def __init__(self, action='hide', message:str=None, password:str=None, method:str='LSB', image_file:str=None, message_file:str=None, output:str=None) -> None:
        self.__action = action
        self.__method = method
        self.__message = message
        self.set_password(password)
        self.set_image(image_file)
        self.set_output(output)
        if action == 'hide':
            self.set_message(message, message_file)

    def __compress_message(self):
        self.__message = gzip.compress(self.__message)
        
    def __decompress_message(self):
        self.__message = gzip.decompress(self.__message)

    def __set_binary_message(self):
        self.__binary_message = Steganography.__convert_to_binary(self.__cipher_bytes)

    def __encrypt_message(self):
        IV_LENGTH = 16
        SALT_LENGTH = 64
        KEY_LENGTH = 32
        HASH_NAME = 'SHA512'
        self.__compress_message()
        iv = get_random_bytes(IV_LENGTH)
        salt = get_random_bytes(SALT_LENGTH)
        secret_key = hashlib.pbkdf2_hmac(HASH_NAME, self.__password.encode(), salt, 210000, KEY_LENGTH)
        cipher = AES.new(secret_key, AES.MODE_GCM, iv)

        encrypted_message_byte, tag = cipher.encrypt_and_digest(self.__message)
        self.__cipher_bytes = iv + salt + encrypted_message_byte + tag

    def __decrypt_message(self):
        IV_LENGTH = 16
        SALT_LENGTH = 64
        KEY_LENGTH = 32
        TAG_LENGTH = 16
        HASH_NAME = 'SHA512'

        iv_start, iv_end = (0, IV_LENGTH)
        salt_start, salt_end = (iv_end, iv_end + SALT_LENGTH)
        cipher_start, cipher_end = (salt_end, len(self.__cipher_bytes)-TAG_LENGTH)
        tag_start = cipher_end

        iv = self.__cipher_bytes[iv_start:iv_end]
        salt = self.__cipher_bytes[salt_start:salt_end]
        cipher = self.__cipher_bytes[cipher_start:cipher_end]
        tag = self.__cipher_bytes[tag_start:]


        secret_key = hashlib.pbkdf2_hmac(HASH_NAME, self.__password.encode(), salt, 210000, KEY_LENGTH)
        decipher = AES.new(secret_key, AES.MODE_GCM, iv)

        try:
            msg = decipher.decrypt_and_verify(cipher, tag)
            self.__message = msg
            self.__decompress_message()
            return True
        except:
            return False
        
    def __set_max_jump(self):
        while True:
            if self.__max_jump == 1: raise Exception('Message too large')
            elif self.__max_jump <= ((self.__rgb_count) / (len(self.__binary_message)*9)) // 1: break
            self.__max_jump = (self.__max_jump*3)//4
        
    def __pixel_jump(self, salt):
        jumper = lambda val: int(xxhash.xxh3_64_hexdigest(val)[0:3], 16)
        cur_jump = int(jumper(self.__password_hash+salt)) % self.__max_jump
        if cur_jump == 0: cur_jump = self.__max_jump
        return cur_jump
        
    def __get_zigzag_pixel_coords(self, coords = None):
        if not coords: return (0, 0, False, False)
        x, y, is_NE, is_SW = coords
        w, h = self.__image_width-1, self.__image_height-1

        go_EAST = lambda x, y: (x+1, y, y != 0, y == 0)
        go_SOUTH = lambda x, y: (x, y+1, x==0, x != 0)
        go_NE = lambda x, y: (x+1, y-1, True, False)
        go_SW = lambda x, y: (x-1, y+1, False, True)

        if x == 0 and y == 0: coords = go_EAST(x, y)

        elif x == 0 and not is_NE and y < h: coords = go_SOUTH(x, y)
        elif y == 0 and not is_SW and x < w: coords = go_EAST(x, y)

        elif x == w and not is_SW: coords = go_SOUTH(x, y)
        elif y == h and not is_NE: coords = go_EAST(x, y)

        elif is_NE: coords = go_NE(x, y)
        elif is_SW: coords = go_SW(x, y)

        return coords

    def __zigzag_change_pixels(self):
        def changer(px_value):
            mult = 1 if random.randint(0, 1) else -1
            if px_value >= 255: mult = -1
            if px_value == 0: mult = 1
            return px_value+mult

        coords = None
        for chunk_index, bits_chunk in enumerate(self.__binary_message):
            values_to_update = ([*bits_chunk[:3]], [*bits_chunk[3:6]], [*bits_chunk[6:]+'1'])
            for value_index, bits in enumerate(values_to_update):
                cur_jump = self.__pixel_jump(str(chunk_index) + str(value_index))
                for _ in range(cur_jump):
                    coords = self.__get_zigzag_pixel_coords(coords)
                x, y = coords[:2]

                RGB = list(self.__image_pxs[x, y])[:]

                for color in range(3):
                    if (RGB[color] % 2 == 0 and bits[color] == '1') or (RGB[color] % 2 == 1 and bits[color] == '0'):
                        RGB[color] = changer(RGB[color])

                if chunk_index == len(self.__binary_message)-1 and value_index == 2: 
                    if RGB[2] % 2 == 1: 
                        RGB[2] = changer(RGB[2])

                self.__image_pxs[x, y] = tuple(RGB)
                
    def __get_zigzag_pixel_with_data(self, loop, coords=None):
        byte_bits = ''
        end_of_message = False
        for value_index in range(3):
            cur_jump = self.__pixel_jump(str(loop) + str(value_index))
            for _ in range(cur_jump):
                coords = self.__get_zigzag_pixel_coords(coords)
            x, y = coords[:2]
            RGB = list(self.__image_pxs[x, y])[:]

            for color in range(3):
                if value_index == 2 and color == 2: end_of_message = RGB[color] % 2 == 0
                elif RGB[color] % 2 == 0: byte_bits += '0'
                else: byte_bits += '1'
        return (byte_bits + ' ', end_of_message, coords)


    def __hide_in_image(self):
        if self.__method == 'LSB':
            self.__encrypt_message()
            self.__set_binary_message()
            self.__set_max_jump()
            self.__zigzag_change_pixels()
            img_byte_arr = BytesIO()
            self.__png.save(img_byte_arr, format='PNG')
            self.__img_with_secret = img_byte_arr.getvalue()

    def __extract_and_decrypt_message(self):
        while self.__max_jump > 1:
            vals = None
            bits_text = ''
            loop = 0
            end_of_message = False
            while not end_of_message:
                byte_bits, end_of_message, vals = self.__get_zigzag_pixel_with_data(loop, vals)
                bits_text += byte_bits
                loop+=1
                
            bits = bits_text.strip().split(' ')
            self.__cipher_bytes = self.__convert_to_text(bits)
            if self.__decrypt_message(): break
            self.__max_jump = (self.__max_jump*3)//4

    def set_image(self, path):
        stream = None
        if path:
            with open(path, 'rb') as raw_image: stream = BytesIO(raw_image.read())
        else:
            while select.select([sys.stdin.buffer], [], [], 1)[0]:
                data = sys.stdin.buffer.read()
                if data: stream = BytesIO(data)
                break

        if not stream: raise Exception('Insert an image')

        self.__png = Image.open(stream).convert('RGB')
        self.__image_width, self.__image_height = self.__png.size
        self.__pixel_count = self.__image_width * self.__image_height
        self.__rgb_count = self.__pixel_count*3
        self.__image_pxs = self.__png.load()
        self.__max_jump = self.__pixel_count

    def set_message(self, message:str|bytes=None, file_path:str=None):
        if type(message) == str: message = message.encode()
        if not message:
            try:
                with open(file_path, 'rb') as msg: message = msg.read()
            except:

                raise Exception('Insert a message or select a file')
        self.__message = message
        return self.__message
    
    def set_password(self, password:str):
        if not password: password = 'password'
        self.__password = password
        self.__password_hash = sha512(password.encode()).hexdigest()


    def set_output(self, path:str):
        if path == 'null':
            self.__output = pathlib.Path('/dev/null')
        elif path == '-' or not path:
            self.__output = None
        else:
            out = pathlib.Path(path)
            self.__output = out
            if out.is_dir():
                filename = f'{secrets.token_hex(16)}.png'
                self.__output = pathlib.Path(f'{path}/{filename}').resolve()
            

    def extract_message(self):
        self.__extract_and_decrypt_message()
        try:
            if self.__output:
                with open(self.__output, 'wb') as output: output.write(self.__message)
            else:
                os.write(1, self.__message)
        except:
            raise Exception('Couldn\'t decrypt')

    def embed(self):
        self.__hide_in_image()
        if self.__output:
            with open(self.__output, 'wb') as raw_image: 
                raw_image.write(self.__img_with_secret)
        else:
            os.write(1, self.__img_with_secret)

    def run(self):
        if self.__action == 'hide':
            self.embed()
        elif self.__action == 'extract':
            self.extract_message()

    
steg = Steganography(args.action, message=args.message, message_file=args.message_file, password=args.password, image_file=args.image_file, output=args.output)

steg.run()