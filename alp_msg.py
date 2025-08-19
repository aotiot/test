import logging

VERBOSE_DEBUG = False

SOH = 0x01
PI1 = 0x41 # A
PI2 = 0x32 # 2
STX = 0x02
ETX = 0x03

class AlpFrame():
    @staticmethod
    def Checksum(frame):
        """Compute a tuple (chksum, chkpar) of a raw (undecoded) ALP frame.

        Computes chksum as a modulo 256 sum of all bytes between STX (frame[3])
        and ETX (frame's fifth to last byte) markers, i.e., of its data field.
        chkpar is the byte-wise exclusive-OR of that same block of data (initial
        value 0). Checks that the frame has enough data and that STX/ETX markers
        are present, returning (0, 0) otherwise.
        """
        flen = len(frame)

        if flen < 10 or frame[3] != STX or frame[flen - 5] != ETX:
            Logger.error("AlpFrame.Checksum(): incorrect frame of size {}".format(flen))
            return (0, 0)

        chksum = 0
        chkpar = 0

        for i in range(4, flen - 5):
            chksum += frame[i]
            chkpar ^= frame[i]

        chksum &= 0xff

        return (chksum, chkpar)

    @staticmethod
    def Encode(b):
        """Encode a byte for data or checksum field.
        """
        b &= 0xff
        return bytes([(b >> 4) + 0x30, (b & 0x0f) + 0x30])

    @staticmethod
    def EncodeData(buffer, offset, data):
        """Encode binary data into a frame's data field, computing the checksum.
        """
        buf_len = len(buffer)
        need_len = len(data) * 2

        if buf_len - offset < need_len:
            Logger.error("AlpFrame.EncodeData(): insufficient buffer size, not encoding")
            return (0, 0)

        j, chksum, chkpar = 0, 0, 0

        for i in range(offset, offset + need_len, 2):
            buffer[i:i+2] = AlpFrame.Encode(data[j])
            chksum += buffer[i] + buffer[i+1]
            chkpar ^= buffer[i]
            chkpar ^= buffer[i+1]
            j += 1

        chksum &= 0xff

        return (chksum, chkpar)

    @staticmethod
    def Decode(b0, b1):
        if b0 < 0x30 or 0x3f < b0 or b1 < 0x30 or 0x3f < b1:
            return None
        else:
            return (int(b0 - 0x30) << 4) | (b1 - 0x30)

    @staticmethod
    def Parse(data):
        """Parse a block of data as an Alp frame.

        Returns a tuple (consumed, nack, frame), where the first component is
        the amount of data parsed (successfully or not), the second one is True
        if there appears to be a frame in the buffer but it is clearly incorrect
        and needs to be resent (complete frame with incorrect checksum,
        incorrect byte sequence, etc.) and the third one is either None or a
        valid Alp frame.
        """
        dlen = len(data)
        if VERBOSE_DEBUG:
            Logger.debug("AlpFrame.Parse(): a buffer of {} bytes".format(dlen))

        # First, find where the frame starts
        if dlen < 9:
            if VERBOSE_DEBUG:
                Logger.debug("AlpFrame.Parse(): too little data to parse, ignoring")
            return (0, False, None)

        start = dlen
        for i in range(dlen - 9 + 1):
            if data[i] == SOH and data[i+1] == PI1 and data[i+2] == PI2:
                start = i
                break

        if start > dlen - 9:
            if VERBOSE_DEBUG:
                Logger.debug("AlpFrame.Parse(): could not find frame start"
                             " byte, consuming whole buffer of size {}".format(dlen))
            return (dlen, False, None)

        # Check for STX
        if data[start + 3] != STX:
            if VERBOSE_DEBUG:
                Logger.debug("AlpFrame.Parse(): no STX found, consuming {} bytes".format(start + 4))
            return (start + 4, True, None)

        # Parse and decode a SNAP frame, computing its checksum in the process
        snap_frame = bytearray((dlen - start - 4) // 2) # NOTE: will overallocate

        j = 0
        offset = start + 4
        chksum = 0
        chkpar = 0

        for i in range(offset, (dlen // 2) * 2 - 2, 2):
            if data[i] == ETX:
                snap_frame[j:] = b'' # Cut the overallocated remainder
                offset = i
                chksum &= 0xff
                break

            chksum += data[i] + data[i+1]
            chkpar ^= data[i]
            chkpar ^= data[i+1]

            b = AlpFrame.Decode(data[i], data[i+1])
            if b is None:
                if VERBOSE_DEBUG:
                    Logger.debug("AlpFrame.Parse(): incorrect byte sequence at"
                                 " offset {}: 0x{:02X} 0x{:02X}, consuming {}"
                                 " bytes".format(i, data[i], data[i+1], i))
                return (i, True, None)

            snap_frame[j] = b

            j += 1

        if data[offset] != ETX or dlen - 5 < offset:
            if VERBOSE_DEBUG:
                Logger.debug("AlpFrame.Parse(): frame's data does not end"
                             " with ETX or no checksum in the frame,"
                             " consuming {} bytes".format(start))
            return (start, False, None)

        # Get and check the validity of the checksum in the byte stream
        fcs = AlpFrame.Decode(data[offset+1], data[offset+2])
        fcp = AlpFrame.Decode(data[offset+3], data[offset+4])
        if fcs is None or fcp is None:
            if VERBOSE_DEBUG:
                Logger.debug("AlpFrame.Parse(): could not decode checksum,"
                             " consuming {} bytes".format(offset))
            return (offset, True, None)

        if fcs != chksum or fcp != chkpar:
            Logger.debug("AlpFrame.Parse(): frame checksum incorrect:"
                         " computed (0x{:02X}, 0x{:02X}), parsed (0x{:02X},"
                         " 0x{:02X}), consuming {} bytes".format(chksum, chkpar,
                         fcs, fcp, offset + 5))
            return (offset + 5, True, None)

        return (offset + 5, False, snap_frame)

    @staticmethod
    def Write(snap_frame):
        fsize = 4 + len(snap_frame) * 2 + 5
        frame = bytearray(fsize)

        frame[0:3] = b'\x01A2'

        frame[3] = STX
        (fcs, fcp) = AlpFrame.EncodeData(frame, 4, snap_frame)
        frame[fsize-5] = ETX

        frame[fsize-4:fsize-2] = AlpFrame.Encode(fcs)
        frame[fsize-2:fsize] = AlpFrame.Encode(fcp)

        return frame

if __name__ != "__main__":
    Logger = logging.getLogger("tapp")
else:
    # Test case data
    valid = b'\x01\x41\x32\x02\x30\x30\x30\x30\x30\x31\x30\x31\x30\x30\x3c\x3a'\
            b'\x30\x30\x3f\x34\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30\x30\x30'\
            b'\x30\x30\x31\x34\x30\x30\x34\x38\x3e\x34\x36\x3c\x37\x39\x37\x34'\
            b'\x37\x39\x37\x33\x32\x30\x32\x30\x32\x30\x32\x30\x32\x30\x32\x30'\
            b'\x32\x30\x32\x30\x32\x30\x32\x30\x32\x30\x32\x30\x32\x30\x03\x39'\
            b'\x31\x30\x31'

    bad_hdr = bytearray(valid)
    bad_hdr[3] = 0

    bad_cs = bytearray(valid)
    bad_cs[len(bad_cs) - 2] += 1

    bad_data_odd = valid[0:10] + valid[11:] # Skip one byte in the data field

    bad_data_seq = bytearray(valid)
    bad_data_seq[15] = 0x29
    
    short_data = valid[0 : len(valid)-10]
    
    no_cs = valid[0 : len(valid)-4]
    no_etx = no_cs[0 : len(no_cs)-1]

    valid_snap = b'\x01\x80\x01\x01\x00\x01\x00\x01\x00\x01\x00\x95\xb8\xf0Y'\
                 b'\x01\x00\xaa'

    # Logging setup
    Logger = logging.getLogger(__name__)
    Logger.setLevel(logging.DEBUG)

    lh = logging.StreamHandler()
    lh.setLevel(logging.DEBUG)
    Logger.addHandler(lh)

    # Test case execution
    def TestParse(test_case):
        name = test_case[0]
        data = test_case[1]
        elist = test_case[2]
        preamble = "Parse() test case \"" + name + "\": "

        Logger.debug(preamble + "{} bytes of data: {}".format(len(data), data))

        offset = 0
        ok = True
        for exp in elist:
            if offset == len(data):
                Logger.debug(preamble + "data consumed but some results still expected, stopping")
                return False

            result = AlpFrame.Parse(data[offset:])
            offset += result[0]
            nack = result[1]
            parsed = True if (result[2] is not None) else False

            if (nack ^ exp[0]) or (parsed ^ exp[1]):
                Logger.debug(preamble + "offset {}: expected {}, {}; returned {}, {}".format(
                        offset, exp[0], exp[1], nack, parsed))
                ok = False

        if ok:
            Logger.debug(preamble + "passed!")
        else:
            Logger.debug(preamble + "unexpected parser results")

        return ok

    def TestWrite(test_case):
        name = test_case[0]
        data = test_case[1]
        preamble = "write() test case \"" + name + "\": "

        Logger.debug(preamble + "{} bytes of data: {}".format(len(data), data))

        encoded = AlpFrame.Write(data)
        (ignore0, nack, parsed) = AlpFrame.Parse(encoded)

        ok = False
        if nack or not parsed:
            Logger.debug(preamble + "written frame could not be parsed: {}".format(encoded))
        elif parsed != data:
            Logger.debug(preamble + "data in the frame parsed back is different"
                         " from the original one:\n"
                         "        {}\n"
                         " vs.    {}".format(snap_frame, data))
        else:
            ok = True

        if ok:
            Logger.debug(preamble + "passed!")
        else:
            Logger.debug(preamble + "unexpected writer results")

        return ok

    # Test case descriptions
    parse_cases = [
            ("empty buffer", b'', [ (False, False) ]),
            ("short garbage", b'abcd', [ (False, False) ]),
            ("long garbage", b'abcdefghi786382773912309812', [ (False, False) ]),
            ("short start", b'abcdefghij\x01A', [ (False, False) ]),
            ("no STX", bad_hdr, [ (True, False) ]),

            ("valid", valid, [ (False, True) ]),
            ("valid after garbage", b'abcdefgh' + valid, [ (False, True) ]),
            ("valid before garbage", valid + b'abcdefgh', [ (False, True) ]),
            ("valid in garbage", b'abcdefgh' + valid + b'abcdefgh', [ (False, True) ]),

            ("two valid", valid + valid, [ (False, True), (False, True) ]),
            ("two valid in garbage", valid + b'abcdefgh' + valid, [ (False, True), (False, True) ]),

            ("bad checksum", bad_cs, [ (True, False) ]),
            ("missing data byte", bad_data_odd, [ (True, False) ]),
            ("incorrect data byte", bad_data_seq, [ (True, False) ]),
            ("short data", short_data, [ (False, False) ]),
            ("no ETX", no_etx, [ (False, False) ]),
            ("no checksum", no_cs, [ (False, False) ]),

            ("short data + valid", short_data + valid, [ (True, False), (False, True) ]),
        ]

    for case in parse_cases:
        Logger.debug("\n======================================")
        TestParse(case)
        Logger.debug("======================================")

    write_cases = [
            ("empty data", b''),
            ("one byte", b'\x01'),
            ("valid SNAP", valid_snap)
        ]

    for case in write_cases:
        Logger.debug("\n======================================")
        TestWrite(case)
        Logger.debug("======================================")

