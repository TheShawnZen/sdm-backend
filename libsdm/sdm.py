# pylint: disable=invalid-name, line-too-long

"""
This code was implemented based on the examples provided in:
* AN12196: NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints
"""

import io
import struct
from enum import Enum
from typing import Callable, Optional

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

import config


class EncMode(Enum):
    AES = 0


class ParamMode(Enum):
    SEPARATED = 0
    BULK = 1


class InvalidMessage(RuntimeError):
    pass


def calculate_sdmmac(param_mode: ParamMode,
                     sdm_file_read_key: bytes,
                     picc_data: bytes,
                     enc_file_data: Optional[bytes] = None,
                     mode: Optional[EncMode] = None) -> bytes:
    if mode is None:
        mode = EncMode.AES

    input_buf = io.BytesIO()

    if enc_file_data:
        sdmmac_param_text = f"&{config.SDMMAC_PARAM}="

        if param_mode == ParamMode.BULK or not config.SDMMAC_PARAM:
            sdmmac_param_text = ""

        input_buf.write(enc_file_data.hex().upper().encode('ascii') + sdmmac_param_text.encode('ascii'))

    sv2stream = io.BytesIO()
    sv2stream.write(b"\x3C\xC3\x00\x01\x00\x80")
    sv2stream.write(picc_data)

    while sv2stream.getbuffer().nbytes % AES.block_size != 0:
        sv2stream.write(b"\x00")

    c2 = CMAC.new(sdm_file_read_key, ciphermod=AES)
    c2.update(sv2stream.getvalue())
    sdmmac = CMAC.new(c2.digest(), ciphermod=AES)
    sdmmac.update(input_buf.getvalue())
    mac_digest = sdmmac.digest()

    return bytes(bytearray([mac_digest[i] for i in range(16) if i % 2 == 1]))


def decrypt_file_data(sdm_file_read_key: bytes,
                      picc_data: bytes,
                      read_ctr: bytes,
                      enc_file_data: bytes,
                      mode: Optional[EncMode] = None) -> bytes:
    if mode is None:
        mode = EncMode.AES

    sv1stream = io.BytesIO()
    sv1stream.write(b"\xC3\x3C\x00\x01\x00\x80")
    sv1stream.write(picc_data)

    while sv1stream.getbuffer().nbytes % AES.block_size != 0:
        sv1stream.write(b"\x00")

    cm = CMAC.new(sdm_file_read_key, ciphermod=AES)
    cm.update(sv1stream.getvalue())
    k_ses_sdm_file_read_enc = cm.digest()
    ive = AES.new(k_ses_sdm_file_read_enc, AES.MODE_ECB) \
        .encrypt(read_ctr + b"\x00" * 13)

    return AES.new(k_ses_sdm_file_read_enc, AES.MODE_CBC, IV=ive) \
        .decrypt(enc_file_data)


def validate_plain_sun(uid: bytes, read_ctr: bytes, sdmmac: bytes, sdm_file_read_key: bytes, mode: Optional[EncMode] = None):
    if mode is None:
        mode = EncMode.AES

    read_ctr_ba = bytearray(read_ctr)
    read_ctr_ba.reverse()

    data_stream = io.BytesIO()
    data_stream.write(uid)
    data_stream.write(read_ctr_ba)

    proper_sdmmac = calculate_sdmmac(ParamMode.SEPARATED,
                                     sdm_file_read_key,
                                     data_stream.getvalue(),
                                     mode=mode)

    if sdmmac != proper_sdmmac:
        raise InvalidMessage("Message is not properly signed - invalid MAC")

    read_ctr_num = struct.unpack('>I', b"\x00" + read_ctr)[0]
    return {
        "encryption_mode": mode,
        "uid": uid,
        "read_ctr": read_ctr_num
    }


def get_encryption_mode(picc_enc_data: bytes):
    if len(picc_enc_data) == 16:
        return EncMode.AES
    raise InvalidMessage("Unsupported encryption mode.")


def decrypt_sun_message(param_mode: ParamMode,
                        sdm_meta_read_key: bytes,
                        sdm_file_read_key: Callable[[bytes], bytes],
                        picc_enc_data: bytes,
                        sdmmac: bytes,
                        enc_file_data: Optional[bytes] = None) -> dict:
    mode = get_encryption_mode(picc_enc_data)

    cipher = AES.new(sdm_meta_read_key, AES.MODE_CBC, IV=b'\x00' * 16)
    plaintext = cipher.decrypt(picc_enc_data)

    p_stream = io.BytesIO(plaintext)
    data_stream = io.BytesIO()

    picc_data_tag = p_stream.read(1)
    uid_mirroring_en = (picc_data_tag[0] & 0x80) == 0x80
    sdm_read_ctr_en = (picc_data_tag[0] & 0x40) == 0x40
    uid_length = picc_data_tag[0] & 0x0F

    uid = None
    read_ctr = None
    read_ctr_num = None
    file_data = None

    if uid_length not in [0x07]:
        calculate_sdmmac(param_mode, sdm_file_read_key(b"\x00" * 7), b"\x00" * 10, enc_file_data, mode=mode)
        raise InvalidMessage("Unsupported UID length")

    if uid_mirroring_en:
        uid = p_stream.read(uid_length)
        data_stream.write(uid)

    if sdm_read_ctr_en:
        read_ctr = p_stream.read(3)
        data_stream.write(read_ctr)
        read_ctr_num = struct.unpack("<I", read_ctr + b"\x00")[0]

    if uid is None:
        raise InvalidMessage("UID cannot be None.")

    file_key = sdm_file_read_key(uid)

    if sdmmac != calculate_sdmmac(param_mode,
                                  file_key,
                                  data_stream.getvalue(),
                                  enc_file_data,
                                  mode=mode):
        raise InvalidMessage("Message is not properly signed - invalid MAC")

    if enc_file_data:
        if not read_ctr:
            raise InvalidMessage("SDMReadCtr is required to decipher SDMENCFileData.")

        file_data = decrypt_file_data(file_key, data_stream.getvalue(),
                                      read_ctr, enc_file_data, mode=mode)

    return {
        "picc_data_tag": picc_data_tag,
        "uid": uid,
        "read_ctr": read_ctr_num,
        "file_data": file_data,
        "encryption_mode": mode
    }
