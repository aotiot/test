import time
from .snap_msg import SNAPMsg

class UplinkAlarm():
    def __init__(self, port_number, snap_msg):
        self.data = {
                "more": "1" if snap_msg.more else "0",
                "msgCounter": "{}".format(snap_msg.message_counter),
                "serviceClass": "{}".format(snap_msg.service_class),
                "msgType": "{}".format(snap_msg.message_type),
                "systemId": "{}".format(snap_msg.system_id),
                "terminalId": "{}".format(snap_msg.terminal_id),
                "loopId": "{}".format(snap_msg.loop_id),
                "eventTime": "{}".format(snap_msg.event_time),
                "data": "".join(chr(i) for i in snap_msg.data)
            }

class DownlinkAlarm(SNAPMsg):
    def __init__(self, on_off, addr=None, data=None):
        SNAPMsg.__init__(self)
        self.empty = False

        if not addr:
            self.system_id, self.terminal_id = 1, 1 # self.loop_id is 0
        else:
            self.system_id, self.terminal_id, self.loop_id = addr

        self.service_class = 1
        self.message_type = 1 if on_off else 9 # 1 - alarm on, 9 - alarm off
        self.message_counter = 1
        self.event_time = int(time.time())

        if data:
            if isinstance(data, str):
                data = data.encode() # UTF-8
            self.data = data
