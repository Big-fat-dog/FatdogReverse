#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KL29 TLV 基准帧生成器。

把 tide.c build_tlv_frame() 产出的“好帧”在编译期烘焙成
app/jni/kl29_tlv_reference.h。运行时 detect_tlv_magic() 把重新构建的帧
与这份独立基准比对：patch build_tlv_frame 的常量/指令后帧内容变化即可检出。
"""
import os
import struct

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JNI = os.path.join(HERE, 'app', 'jni')
HEADER = os.path.join(JNI, 'kl29_tlv_reference.h')

TLV_MAGIC = 0x4644544C
TLV_TYPE_REQ = 0x0001
TLV_PAGE = 1
TLV_TS = 20280723

frame = struct.pack('<III', TLV_MAGIC, TLV_TYPE_REQ, 12)
frame += struct.pack('<I', TLV_PAGE)
frame += struct.pack('<Q', TLV_TS)
assert len(frame) == 24, len(frame)

bytes_line = ','.join('0x%02x' % b for b in frame)
lines = [
    '#ifndef KL29_TLV_REFERENCE_H',
    '#define KL29_TLV_REFERENCE_H',
    '',
    '/* 自动生成：tools/gen_tlv_reference.py，请勿手改。 */',
    '#define KL29_TLV_REFERENCE_LEN %d' % len(frame),
    '#define KL29_TLV_REFERENCE_BYTES {%s}' % bytes_line,
    '',
    '#endif /* KL29_TLV_REFERENCE_H */',
    '',
]
with open(HEADER, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(lines))
print('wrote', os.path.relpath(HEADER, HERE), '(%d bytes)' % len(frame))
