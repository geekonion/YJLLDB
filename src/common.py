# -*- coding: UTF-8 -*-
import hashlib
g_byteorder = 'little'


def get_int(base: bytes, offset, byteorder=None):
    if byteorder:
        return int.from_bytes(base[offset:offset + 4], byteorder=byteorder)
    else:
        return int.from_bytes(base[offset:offset + 4], byteorder=g_byteorder)


def get_long(base: bytes, offset, byteorder=None):
    if byteorder:
        return int.from_bytes(base[offset:offset + 8], byteorder=byteorder)
    else:
        return int.from_bytes(base[offset:offset + 8], byteorder=g_byteorder)


def get_string(base: bytes, offset, length=0):
    if length == 0:
        pos = base.find(b'\x00', offset)
        length = pos - offset
    return base[offset:offset + length].strip(b'\x00').decode()


def swap32(num):
    return (((num << 24) & 0xFF000000) |
            ((num << 8) & 0x00FF0000) |
            ((num >> 8) & 0x0000FF00) |
            ((num >> 24) & 0x000000FF))


def get_cs_super_blob(base: bytes, offset, byteorder=None):
    magic = swap32(get_int(base, offset, byteorder))
    length = get_int(base, offset + 4, byteorder)
    count = swap32(get_int(base, offset + 8, byteorder))

    return magic, length, count


def get_cs_blob_index(base: bytes, offset, byteorder=None):
    data_type = get_int(base, offset, byteorder)
    data_offset = swap32(get_int(base, offset + 4, byteorder))

    return data_type, data_offset


def get_cs_blob(base: bytes, offset, byteorder=None):
    magic = swap32(get_int(base, offset, byteorder))
    length = swap32(get_int(base, offset + 4, byteorder))

    return magic, length


def file_md5(file_path):
    md5_hash = hashlib.md5()
    with open(file_path, 'rb') as file:
        while True:
            data = file.read(4096)
            if not data:
                break
            md5_hash.update(data)

    return md5_hash.hexdigest()
