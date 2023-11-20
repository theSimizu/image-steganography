#!venv/bin/python

import sys
import argparse
import random
import xxhash
import hashlib
from hashlib import sha256
from PIL import Image
from io import BytesIO
from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes


parser = argparse.ArgumentParser()

parser.add_argument('action', nargs='?')
parser.add_argument("-piu", "--pipeimageupload", help="FIFO with image data")
parser.add_argument("-pid", "--pipeimagedownload", help="FIFO with image data")
parser.add_argument("-pmu", "--pipemessageupload", help="FIFO with message data")
parser.add_argument("-pmd", "--pipemessagedownload", help="FIFO with message data")
parser.add_argument("-pw", "--password", help="FIFO with message data")
parser.add_argument("-ph", "--pipepasshash", help="FIFO with message data")

args = parser.parse_args()

class Steganography:
    def __init__(self, action) -> None:
        self.__set_image()
        self.__set_encrypted_message()
        self.__set_password()
        if action == 'hide':
            self.__set_max_jump()
        elif action == 'extract':
            self.__set_extract_jump()

    def __encrypt_message(self):
        SALT_LENGTH = 64
        IV_LENGTH = 16
        HASH_NAME = 'SHA512'
        KEY_LENGTH = 32
        password = ''
        message = self.message

        salt = get_random_bytes(SALT_LENGTH) 
        iv = get_random_bytes(IV_LENGTH)

        secret_key = hashlib.pbkdf2_hmac(HASH_NAME, password, salt, 100001, KEY_LENGTH)

        cipher = AES.new(secret_key, AES.MODE_GCM, iv)

        encrypted_message_byte, tag = cipher.encrypt_and_digest(message)

        cipher_byte = iv + salt + encrypted_message_byte + tag

        




    def __set_encrypted_message(self):
        try:
            with open(args.pipemessageupload, 'r') as msg: 
                self.bits_list = msg.read().split(' ')
        except:
            pass

    def __set_extract_jump(self):
        self.max_jump = 256

    def __set_password(self):
        password = args.password
        self._hash = sha256(password.encode()).hexdigest()

    def __set_max_jump(self):
        self.max_jump = 256
        while True:
            if self.max_jump <= ((self.pixel_count*3) / (len(self.bits_list)*9)) // 1: break
            elif self.max_jump == 1: print('erro')
            self.max_jump //= 2

    def __set_image(self):
        with open(args.pipeimageupload, 'rb') as raw_image:
            stream = BytesIO(raw_image.read())
            raw_image.close()
            self.png = Image.open(stream).convert('RGB')
            self.width, self.height = self.png.size
            self.pixel_count = self.width * self.height

            self.cur_index_normal = 0
            self.cur_index_reverse = self.pixel_count

            self.pxs = self.png.load()

    def __randomize_pixels(self):
        for y in range(self.height):
            for x in range(self.width):
                RGB = list(self.pxs[x, y])
                for bits in range(3):
                    if random.randint(0, 1):
                        RGB[bits] -= 1 if RGB[bits] > 0 else RGB[bits] + 1
                self.pxs[x, y] = tuple(RGB)

    def __pixel_jump(self, salt):
        jumper = lambda val: int(xxhash.xxh3_64_hexdigest(val)[0:3], 16)
        cur_jump = int(self._hash[jumper(salt) % 64], 16)
        cur_jump = (cur_jump + jumper(str(cur_jump))) % self.max_jump
        if cur_jump == 0: cur_jump = self.max_jump
        return cur_jump

    def __change_pixels(self):
        for chunk_index, bits_chunk in enumerate(self.bits_list):
            values_to_update = ([*bits_chunk[:3]], [*bits_chunk[3:6]], [*bits_chunk[6:]+'1'])
            for value_index, bits in enumerate(values_to_update):
                cur_jump = self.__pixel_jump(str(chunk_index) + str(value_index))
                if chunk_index % 2 == 0:
                    self.cur_index_normal += cur_jump
                    x = self.cur_index_normal % self.width
                    y = self.cur_index_normal // self.width
                else:
                    self.cur_index_reverse -= cur_jump
                    x = self.cur_index_reverse % self.width
                    y = self.cur_index_reverse // self.width

                RGB = list(self.pxs[x, y])[:]
                for color in range(0, 3):
                    if (RGB[color] % 2 == 0 and bits[color] == '1') or (RGB[color] % 2 == 1 and bits[color] == '0'):
                        if RGB[color] < 255: RGB[color] += 1
                        else: RGB[color] -= 1


                if chunk_index == len(self.bits_list)-1 and value_index == 2: 
                    if RGB[2] % 2 == 1: 
                        if RGB[2] < 255: RGB[2] += 1
                        else: RGB[2] -= 1

                self.pxs[x, y] = tuple(RGB)

    def __hide_data(self):
        self.__randomize_pixels()
        self.__change_pixels()
        img_byte_arr = BytesIO()
        self.png.save(img_byte_arr, format='PNG')
        self.img_with_secret = img_byte_arr.getvalue()

    def image_upload(self):
        self.__hide_data()
        with open(args.pipeimagedownload, 'wb') as raw_image:
            raw_image.write(self.img_with_secret)

    def extract_message(self):
        bits_text = ''
        loop = 0
        end_of_message = False
        while not end_of_message:
            byte = ''
            for value_index in range(3):
                cur_jump = self.__pixel_jump(str(loop) + str(value_index))


                if loop % 2 == 0:
                    self.cur_index_normal += cur_jump
                    x = self.cur_index_normal % self.width
                    y = self.cur_index_normal // self.width
                else:
                    self.cur_index_reverse -= cur_jump
                    x = self.cur_index_reverse % self.width
                    y = self.cur_index_reverse // self.width

                RGB = list(self.pxs[x, y])[:]
                for color in range(3):
                    if value_index == 2 and color == 2:
                        if RGB[color] % 2 == 1:
                            continue
                        else:
                            end_of_message = True
                            continue

                    if RGB[color] % 2 == 0: byte += '0'
                    else: byte += '1'

            bits_text += byte + ' '

            loop+=1
        self.message = bits_text.strip()


    def upload_message(self):
        self.extract_message()
        with open(args.pipemessagedownload, 'w') as message:
            message.write(self.message)









steg = Steganography(args.action)

if args.action == 'hide':
    steg.image_upload()
elif args.action == 'extract':
    steg.upload_message()