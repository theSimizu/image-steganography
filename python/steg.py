#!venv/bin/python
import os
import sys
import argparse
import random
import xxhash
import hashlib
import select
import pathlib
import secrets
from hashlib import sha256, sha512
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
        self.set_password(password)
        self.set_image(image_file)
        self.set_output(output)
        if action == 'hide':
            self.set_message(message, message_file)


    def __encrypt_message(self):
        IV_LENGTH = 16
        SALT_LENGTH = 64
        KEY_LENGTH = 32
        HASH_NAME = 'SHA512'

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
            self.__message = msg.decode()
            return True
        except:
            return False
        
    def __set_binary_message(self):
        self.__binary_message = Steganography.__convert_to_binary(self.__cipher_bytes)

    def __set_max_jump(self):
        self.__max_jump = self.__pixel_count
        while True:
            if self.__max_jump <= ((self.__rgb_count) / (len(self.__binary_message)*9)) // 1: break
            elif self.__max_jump == 1: raise Exception('File too large')
            self.__max_jump = (self.__max_jump*3)//4

    def __randomize_pixels(self):
        for y in range(self.__image_height):
            for x in range(self.__image_width):
                RGB = list(self.__image_pxs[x, y])[:]
                if not random.randint(0, 5):
                    bits = random.randint(0, 2)
                    RGB[bits] -= 1 if RGB[bits] > 0 else RGB[bits] + 1
                # self.__image_pxs[x, y] = tuple(RGB)

    def __pixel_jump(self, salt):
        jumper = lambda val: int(xxhash.xxh3_64_hexdigest(val)[0:3], 16)
        cur_jump = int(jumper(self.__password_hash+salt)) % self.__max_jump
        if cur_jump == 0: cur_jump = self.__max_jump
        return cur_jump

    def __get_current_pixel(self, index1, index2):
        cur_jump = self.__pixel_jump(str(index1) + str(index2))
        if index1 % 2 == 0:
            self.__cur_index_normal += cur_jump
            x = self.__cur_index_normal % self.__image_width
            y = self.__cur_index_normal // self.__image_width
        else:
            self.__cur_index_reverse -= cur_jump
            x = self.__cur_index_reverse % self.__image_width
            y = self.__cur_index_reverse // self.__image_width

        return (x, y)

    def __change_pixels(self):
        changer: int = lambda val: val+1 if val < 255 else val-1
        for chunk_index, bits_chunk in enumerate(self.__binary_message):
            values_to_update = ([*bits_chunk[:3]], [*bits_chunk[3:6]], [*bits_chunk[6:]+'1'])
            for value_index, bits in enumerate(values_to_update):
                x, y = self.__get_current_pixel(chunk_index, value_index)
                RGB = list(self.__image_pxs[x, y])[:]

                for color in range(3):
                    if (RGB[color] % 2 == 0 and bits[color] == '1') or (RGB[color] % 2 == 1 and bits[color] == '0'):
                        RGB[color] = changer(RGB[color])

                if chunk_index == len(self.__binary_message)-1 and value_index == 2: 
                    if RGB[2] % 2 == 1: 
                        RGB[2] = changer(RGB[2])

                self.__image_pxs[x, y] = tuple(RGB)

    def __hide_in_image(self):
        if self.__method == 'LSB':
            self.__encrypt_message()
            self.__set_binary_message()
            self.__set_max_jump()
            self.__randomize_pixels()
            self.__change_pixels()
            img_byte_arr = BytesIO()
            self.__png.save(img_byte_arr, format='PNG')
            self.__img_with_secret = img_byte_arr.getvalue()

    def __get_modified_pixels_values(self, loop):
        byte_bits = ''
        end_of_message = False
        for value_index in range(3):
            x, y = self.__get_current_pixel(loop, value_index)
            RGB = list(self.__image_pxs[x, y])[:]

            for color in range(3):
                if value_index == 2 and color == 2: end_of_message = RGB[color] % 2 == 0
                elif RGB[color] % 2 == 0: byte_bits += '0'
                else: byte_bits += '1'
        return (byte_bits + ' ', end_of_message)

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
        self.__cur_index_normal = 0
        self.__cur_index_reverse = self.__pixel_count
        self.__image_pxs = self.__png.load()

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
        if path == '-' or not path:
            self.__output = None
        else:
            out = pathlib.Path(path)
            self.__output = out
            if out.is_dir():
                filename = f'{secrets.token_hex(16)}.png'
                self.__output = pathlib.Path(f'{path}/{filename}').resolve()
            

    def extract_message(self):
        self.__max_jump = self.__pixel_count
        while self.__max_jump > 1:
            self.__cur_index_normal = 0
            self.__cur_index_reverse = self.__pixel_count
            bits_text = ''
            loop = 0
            end_of_message = False
            while not end_of_message:
                byte_bits, end_of_message = self.__get_modified_pixels_values(loop)
                bits_text += byte_bits
                loop+=1
                
            bits = bits_text.strip().split(' ')
            self.__cipher_bytes = self.__convert_to_text(bits)
            if self.__decrypt_message(): break
            self.__max_jump = (self.__max_jump*3)//4
            
        try:
            if self.__output:
                with open(self.__output, 'wb') as output:
                    output.write(self.__message.encode())
            else:
                os.write(1, self.__message.encode())
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



# steg.set_message(args.message, args.message_file)
# if hasattr(args, 'image_path'):
#     steg.set_image(args.image_path)
# steg.set_password(args.password)
# steg.run(args.output_file)

# print(pathlib.Path().resolve())
# print(pathlib.Path('/home/barney/Pictures/jojo.png').resolve())

# steg.set_message(args.message, args.message_file)


# print(args.output_file)


# hide = Steganography('hide', '123456789', 'teste', image_file='/home/barney/Pictures/kkkkkk.png')
# hide = Steganography('hide', 'asdffgdfgd', 'teste')
# extract = Steganography('extract', 'teste', 'teste')
# hide.set_image('/home/barney/Downloads/Screenshot_20231105_114537 (1).png')
# extract.set_image('/home/barney/Downloads/Screenshot_20231105_114537 (1).png')
# hide.set_message(file_path='/home/barney/.electrum/wallets/default_wallet')
# extract.set_password('test')
# extract.set_image('/home/barney/Downloads/abc.png')
# hide.save('/home/barney/Downloads/abc.png')
# extract.extract_message()
# steg.__encrypt_message()

# if args.action == 'hide':
#     steg.image_upload()
# elif args.action == 'extract':
#     steg.upload_message()
