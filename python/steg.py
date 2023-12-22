#!venv/bin/python
import os
import sys
import argparse
import random
import xxhash
import select
import pathlib
import secrets
import math
import numpy as np
from cry import Crypt
from io import BytesIO
from PIL import Image
from hashlib import sha512


parser = argparse.ArgumentParser()

parser.add_argument('action', nargs='?', choices=['embed', 'extract'])
parser.add_argument('-m', '--message')
parser.add_argument('-p', '--password')
parser.add_argument('-mt', '--method')
parser.add_argument('-if', '--image_file')
parser.add_argument('-mf', '--message_file')
parser.add_argument('-o', '--output')

args = parser.parse_args()

class Steganography:
    @staticmethod
    def __text_to_bits(cipher_bytes:bytes):
        return [format(x, 'b').zfill(8) for x in cipher_bytes]
    
    @staticmethod
    def __bits_to_text(binary:list[str]):
        text = ''.join([format(int(txt, 2), 'x').zfill(2) for txt in binary])
        return bytes.fromhex(text)
    
    def __init__(self, action='hide', message:str=None, password:str=None, method:str='LSB', image_file:str=None, message_file:str=None, output:str=None) -> None:
        self.__action = action
        self.__method = method
        self.__message = message
        self.__message_chunk_size = 1
        self.set_password(password)
        self.set_image(image_file)
        self.set_output(output)
        if action == 'hide':
            self.set_message(message, message_file)

    def __recover_from_hamming_code(self, cover):
        if type(cover) == str or type(cover) == list[str]: cover = [int(x) for x in cover]

        cover = np.array(cover)
        size = int(math.log2(len(cover)+1))

        indexes_with_1 = [[int(c, 2) for c in bin(index+1)[2:].zfill(size)] for index, val in enumerate(cover) if val]
        indexes_with_1.append([0 for _ in range(size)]) # Avoid error if cover is full 0

        transposed_values = np.array(indexes_with_1).transpose()
        xor_current_values = np.array([a.sum()%2 for a in transposed_values])

        return xor_current_values


    def __hamming_code_bits_change(self, message, cover):
        if type(message) == str or type(message) == list[str]: message = [int(x) for x in message]
        if type(cover) == str or type(cover) == list[str]: cover = [int(x) for x in cover]

        message = np.array(message)
        cover = np.array(cover)

        size = len(message)
        if 2 ** size != len(cover)+1: raise Exception('Incompatible message and cover size')

        indexes_with_1 = [[int(c, 2) for c in bin(index+1)[2:].zfill(size)] for index, val in enumerate(cover) if val]
        indexes_with_1.append([0 for _ in range(size)]) # Avoid error if cover is full 0

        transposed_values = np.array(indexes_with_1).transpose()
        xor_current_values = np.array([a.sum()%2 for a in transposed_values])

        difference = (xor_current_values - message) % 2
        index_to_change = ''.join(difference.astype(str))
        index_to_change = int(index_to_change, 2) -1

        if index_to_change > -1: cover[index_to_change] = not cover[index_to_change]
        return cover
        
    def __set_max_jump(self):
        self.__max_jump = 2
        while ((self.__rgb_count) / (len(self.__binary_message) * 9 * 2**self.__message_chunk_size-1)) > 2:
            self.__message_chunk_size += 1
        if self.__message_chunk_size == 1: raise Exception('Message too large')
        self.__cover_chunk_size = 2**self.__message_chunk_size-1
        
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
        amount_of_pixels_to_hide_data = -(-(2 ** self.__message_chunk_size -1) // 3)
        bin_message = [chunk+str(int(index != len(self.__binary_message)-1)) for index, chunk in enumerate(self.__binary_message)]
        bin_message = ''.join(bin_message)
        bin_message += '0' * (-len(bin_message) % self.__message_chunk_size)
        chunked_message = [bin_message[x:x+self.__message_chunk_size] for x in range(0, len(bin_message), self.__message_chunk_size)]
        for message_index, message in enumerate(chunked_message):
            altered_pixels_coords = []
            pixels_LSBs_cover = ''
            for _ in range(amount_of_pixels_to_hide_data):
                cur_jump = self.__pixel_jump(str(message_index) + str(_))
                for _ in range(cur_jump):
                    coords = self.__get_zigzag_pixel_coords(coords)
                x, y = coords[:2]
                altered_pixels_coords.append((x, y))
                LSBs = tuple(map(lambda e: str(e%2), tuple(self.__image_pxs[x, y])))
                pixels_LSBs_cover += ''.join(LSBs)
            
            altered_LSBs = tuple(self.__hamming_code_bits_change(message, pixels_LSBs_cover[:self.__cover_chunk_size]))
            new_pixels_LSBs = tuple(altered_LSBs[x:x+3] for x in range(0, len(altered_LSBs), 3))

            for index in range(len(altered_pixels_coords)):
                x, y = altered_pixels_coords[index]
                pixel_values_pre_change = list(self.__image_pxs[x, y])
                new_values_LSB = new_pixels_LSBs[index]
                for i in range(len(new_values_LSB)):

                    if pixel_values_pre_change[i] % 2 != new_values_LSB[i]: 
                        pixel_values_pre_change[i] = changer(pixel_values_pre_change[i])
                        # pixel_values_pre_change[i] = 255
                
                self.__image_pxs[x, y] = tuple(pixel_values_pre_change)
    

    
    def __get_zigzag_pixel_with_data(self, loop, coords=None):
        try:
            byte_bits = ''
            end_of_message = False
            amount_of_pixels_to_hide_data = -(-(2 ** self.__message_chunk_size -1) // 3)
            
            for a in range(amount_of_pixels_to_hide_data):
                cur_jump = self.__pixel_jump(str(loop) + str(a))
                for _ in range(cur_jump):
                    coords = self.__get_zigzag_pixel_coords(coords)
                x, y = coords[:2]
                RGB = list(self.__image_pxs[x, y])[:]
                for color in range(3):
                    byte_bits += str(RGB[color] % 2)
            msg = self.__recover_from_hamming_code(byte_bits[:2 ** self.__message_chunk_size -1])

            return (''.join(map(lambda x: str(x), msg)), end_of_message, coords)
        except:
            raise Exception("Coudn't decrypt")
                
    def __hide_in_image(self):
        if self.__method == 'LSB':
            cry = Crypt(self.__message, self.__password.encode())
            encrypted_message = cry.encrypt_message()
            self.__binary_message = Steganography.__text_to_bits(encrypted_message)
            self.__set_max_jump()
            self.__zigzag_change_pixels()
            img_byte_arr = BytesIO()
            self.__png.save(img_byte_arr, format='PNG')
            self.__img_with_secret = img_byte_arr.getvalue()

    def __extract_and_decrypt_message(self):
        self.__max_jump = 2
        self.__message_chunk_size = 1
        while True:
            coords = None
            bits_text = ''
            loop = 0
            end_of_message = False
            bits = []
            while not end_of_message:
                byte_bits, end_of_message, coords = self.__get_zigzag_pixel_with_data(loop, coords)
                bits_text += byte_bits
                bits = [bits_text[b:b+9] for b in range(0, len(bits_text), 9)]
                for bit in bits:
                    if len(bit) == 9 and bit[8] == '0': end_of_message = True

                loop+=1

            bits = [x[:8] for x in bits]
            if len(bits[-1]) < 8: bits.pop()
            self.__cipher_bytes = self.__bits_to_text(bits)
            cry = Crypt(self.__cipher_bytes, self.__password.encode())

            self.__message = cry.decrypt_message()
            if self.__message: break
            self.__message_chunk_size+=1


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
        try:
            self.__png = Image.open(stream).convert('RGB')
            self.__image_width, self.__image_height = self.__png.size
            self.__pixel_count = self.__image_width * self.__image_height
            self.__rgb_count = self.__pixel_count*3
            self.__image_pxs = self.__png.load()
            self.__max_jump = self.__pixel_count
        except:
            raise Exception('Cannot identify image')

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
        if self.__action == 'embed':
            self.embed()
        elif self.__action == 'extract':
            self.extract_message()

    
steg = Steganography(args.action, message=args.message, message_file=args.message_file, password=args.password, image_file=args.image_file, output=args.output)

steg.run()