import os
from rich import inspect

def is_jpeg(img):
    file_signature = img.read(2)
    img.seek(0)
    # print(file_signature)
    return file_signature == b'\xFF\xD8'

def is_png(img):
    # print(img)
    file_signature = img.read(8)
    img.seek(0)
    # print(file_signature)
    return file_signature[:4] == b'\x89PNG' and file_signature[4:] == b'\r\n\x1A\n'

def is_less_than_max_file_size(file, max_size_mb=5):
    max_size_bytes = max_size_mb * 1024 * 1024

    file_size = len(file.stream.read())
    file.stream.seek(0)
    # print(file_size <= max_size_bytes)
    return file_size <= max_size_bytes

def is_valid_image(image):
    # inspect(image)
    _, file_extension = os.path.splitext(image.filename.lower())
    # print(file_extension)
    if file_extension == '.jpeg' or file_extension == '.jpg':
        return is_jpeg(image)
    elif file_extension == '.png':
        # print('HERE')
        return is_png(image) 
    else:
        return False