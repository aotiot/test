import time
from .port_base import PortBase
from .alp_msg import AlpFrame
from .snap_msg import SNAPMsg
from .alp_messages import *

VERBOSE_DEBUG = True

# Control chars
ACK = b'\x06' # Positive acknowledge
NAK = b'\x15' # Negative acknowledge
ENQ = b'\x05' # Transmit request
EOT = b'\x04' # No messages

DIAGNOSTICS_INTERVAL = 5

RESEND_LIMIT = 10 # Retransmit attempts until line alarm is raised
RESEND_LIMIT_NAK = 5

SESSION_IDLE            = 0
SESSION_ACTIVE_MASTER   = 1
SESSION_ACTIVE_CLIENT   = 2
SESSION_FINISHED        = 3

MESSAGE_STATE_CREATED             = 0
MESSAGE_STATE_SENT                = 1
MESSAGE_STATE_ACKED               = 2
MESSAGE_STATE_NACKED              = 3
MESSAGE_STATE_NO_REPLY            = 4
MESSAGE_STATE_SEND_FAILED         = 5

# According to SNAP Specification maximum len for SNAP msg is 1017 including header parts
RX_BUFFER_MAX_LEN = 1024

DEFAULT_SETTINGS = {
        'inter_byte_timeout': None,
        'baudrate': 9600,
        'rtscts': False,
        'dsrdtr': False,
        'stopbits': 1,
        'bytesize': 8,
        'xonxoff': False,
        'parity': 'N',
        'timeout': 2.0,
        'write_timeout': 2.0
    }

class AlpPort(PortBase):
    def __init__(self, number, serial_snap_proto="hhl"):
        PortBase.__init__(self, number, serial_snap_proto, DEFAULT_SETTINGS)
        self.logger.debug(self.name + ": creating ALPport with serial snap proto: " + serial_snap_proto)
        self.serial_snap_proto = serial_snap_proto
        self.message_counter = 0
        self.session_state = SESSION_IDLE
        self.downlink_buffer = ""
        self.downlink_retransmit_count = 0 # Diagnostic counter for message retransmit attempts

        current_time = time.time()
        self.latest_downlink_event_time = current_time
        self.latest_uplink_event_time = current_time
        self.active_faults = []
        self.line_fault_over_msg_sent = False

        if self.open():
            self.diag_timer = self.add_timeout_seconds(DIAGNOSTICS_INTERVAL,
                    self.session_diagnostics)

    def send_generic_alarm(self, on_off, alrm_src=None, contents=None):
        """Send a generic alarm message to the downlink.

        Sends out a SNAP message with service class 1, address 1.1.x (x depends
        on alrm_src[2] or is 0 if alrm_src is None) and of type 1 (alarm on) or
        9 (alarm off). alrm_src is either None (unspecified source) or a tuple
        (network, device, loop), identifying the network, device and sensor that
        has generated the alarm state event. The first two tuple elements are
        ignored.
        """
        if not self.port:
            self.logger.debug(self.name + " send_generic_alarm(): port not open")
            return

        if "linefault" in self.active_faults:
            self.logger.warning(self.name + ": line fault in the port, may not"
                                " be able to deliver the alarm message")

        if not (alrm_src and isinstance(alrm_src, tuple) and 3 <= len(alrm_src) and alrm_src[2]):
            loop_id = 0
        else:
            loop_id = alrm_src[2]
        self.transmit(DownlinkAlarm(on_off, (1, 1, loop_id), contents))

    ''' ------------------ '''
    ''' Session Management '''
    ''' ------------------ '''

    def session_is_active(self):
        if (self.session_state == SESSION_IDLE) or (self.session_state == SESSION_FINISHED):
            return False
        return True

    def session_begin(self, state=SESSION_ACTIVE_MASTER):
        self.session_state = state
        self.downlink_buffer = ""

    def session_finish(self):
        self.downlink_retransmit_count = 0
        self.downlink_buffer = ""
        self.session_state = SESSION_FINISHED

    def session_diagnostics(self):
        if not self.port:
            self.logger.debug(self.name + " session_diagnostics(): port not open, exiting")
            self.remove_source(self.diag_timer, skip_glib=True)
            return False

        current_time = time.time()
        if self.session_is_active():
            if current_time - self.latest_downlink_event_time >= 4.5:
                self.re_transmit(MESSAGE_STATE_NO_REPLY)
        else:
            self.session_state = SESSION_IDLE
            if current_time - self.latest_uplink_event_time >= 19.5:
                self.send_enq()

        return True

    ''' ------------------------ '''
    ''' Communication Management '''
    ''' ------------------------ '''

    def transmit(self, snap_msg):
        if VERBOSE_DEBUG:
            snap_msg.log_contents(self.name + ": transmitting SNAP message:")
        if not self.port:
            self.logger.debug(self.name + " transmit(): port not open, exiting")
            return

        if self.session_is_active() is False:
            self.session_begin(SESSION_ACTIVE_MASTER)

        self.downlink_buffer = AlpFrame.Write(snap_msg.write())
        self.latest_downlink_event_time = time.time()
        self.write(self.downlink_buffer)
        self.message_counter = self.message_counter + 1

    def transmit_control_char(self, char):
        if self.session_is_active() is False:
            self.session_begin(SESSION_ACTIVE_MASTER)

        self.latest_downlink_event_time = time.time()
        self.downlink_buffer = char
        self.write(self.downlink_buffer, flush=True)

    def re_transmit(self, message_state):
        if message_state == MESSAGE_STATE_NACKED:
            resend_limit = RESEND_LIMIT_NAK
        else:
            resend_limit = RESEND_LIMIT

        if self.downlink_retransmit_count < resend_limit:
            self.downlink_retransmit_count += 1
            self.logger.debug(self.name + ": retransmitting ({}/{}): {}".format(self.downlink_retransmit_count, resend_limit, self.downlink_buffer))
            self.latest_downlink_event_time = time.time()
            self.write(self.downlink_buffer)
        elif self.downlink_retransmit_count == resend_limit:
            self.session_finish()
            if "linefault" not in self.active_faults:
                self.active_faults.append("linefault")
                self.send_fault_detected("linefault", "No reply within retransmit count limit")
                self.logger.info(self.name + ": LINE ALARM - no reply within retransmit count limit")

    ''' --------------- '''
    ''' Uplink Handlers '''
    ''' --------------- '''

    def check_control_char(self, data):
        char = None if (not data) else data[0:1]
        is_cchar = True

        if char == ACK:
            if VERBOSE_DEBUG:
                self.logger.debug(self.name + ": received ACK")
            self.session_finish()
        elif char == NAK:
            if VERBOSE_DEBUG:
                self.logger.debug(self.name + ": received NAK")
            self.re_transmit(MESSAGE_STATE_NACKED)
        elif char == EOT:
            if VERBOSE_DEBUG:
                self.logger.debug(self.name + ": received EOT")
            self.session_finish()
        elif char == ENQ:
            if VERBOSE_DEBUG:
                self.logger.debug(self.name + ": received ENQ")
            self.send_eot()
            self.session_finish()
        else:
            is_cchar = False

        return is_cchar

    def on_receive(self, data):        
        self.logger.debug(self.name + ": received {} bytes of data: {}".format(len(data), data))

        valid_msg_parsed = False
        consumed = 1
        while consumed and len(data):
            if self.check_control_char(data):
                consumed, nack, snap_frame = 1, False, None
                valid_msg_parsed = True
            else:
                consumed, nack, snap_frame = AlpFrame.Parse(data)

            if consumed != 0:
                self.consume_rx_buffer(consumed)
                data = self.rx_buffer

            if nack:
                self.send_nak()
            elif not snap_frame:
                if not consumed and len(data) >= RX_BUFFER_MAX_LEN:
                    # Execution comes here if data is received in chunks and
                    # valid protocol ID has been received (SOH+A2+STX) but despite
                    # of receiving large amount of data ETX char has not been received.
                    self.logger.debug(self.name + ": Data length Exceeds RX_BUFFER_LENTH. Discarding data: {}".format(data)) # New debugging for HHL-C linefaults
                    self.clear_rx_buffer()
                    self.send_nak()
                    self.session_finish()
            else:
                if not self.session_is_active():
                    self.session_begin(SESSION_ACTIVE_CLIENT)

                msg = SNAPMsg.Parse(snap_frame)
                if not msg.empty:
                    valid_msg_parsed = True
                    if self.serial_snap_proto == "hhl":
                        self.on_message_hhl(msg)
                    elif self.serial_snap_proto == "prodex":
                        self.on_message_prodex(msg)
                    else:
                        self.logger.debug(self.name + ": unknown serial_snap_proto: {}".format(self.serial_snap_proto))

                self.send_ack()

        if not len(data):
            if VERBOSE_DEBUG:
                self.logger.debug(self.name + ": Empty data.Closing session.")
            self.session_finish()

        if valid_msg_parsed:
            self.latest_uplink_event_time = time.time()
            if "linefault" in self.active_faults or not self.line_fault_over_msg_sent:
                self.logger.info(self.name + ": linefault over")
                if "linefault" in self.active_faults:
                    self.active_faults.remove("linefault")
                if not self.line_fault_over_msg_sent:
                    self.line_fault_over_msg_sent = True
                self.send_fault_over("linefault over")

    def on_message_hhl(self, msg):
        content = "non-specified"

        if msg.more and VERBOSE_DEBUG:
            self.logger.debug(self.name + ": on_message_hhl(): more bit is set")

        # Parse msg to get msg type code
        if msg.service_class == 1:
            if msg.message_type == 1:
                if msg.loop_id == 0:
                    content = "Keskuksen linjahalytys"
                elif msg.loop_id >= 1 and msg.loop_id <= 512:
                    content = "Silmukka auki (halytys)"
                elif msg.loop_id >= 521 and msg.loop_id <= 552:
                    content = "Poliisipainike"
                elif msg.loop_id >= 561 and msg.loop_id <= 592:
                    content = "Kayttolaitteen kansi auki"
                elif msg.loop_id == 600:
                    content = "Keskus osavalvontatilaan"
                elif msg.loop_id >= 601 and msg.loop_id <= 632:
                    content = "Ryhma kytketty pois"
                elif msg.loop_id == 680:
                    content = "Keskuksen kuittaustieto"
                elif msg.loop_id == 681:
                    content = "Akkuhalytys"
                elif msg.loop_id == 682:
                    content = "Keskuksen kansi auki"
                elif msg.loop_id == 683:
                    content = "Vaara koodi syotetty"
                elif msg.loop_id == 691:
                    content = "Vajaatoiminta (paalle)"
                elif msg.loop_id >= 701 and msg.loop_id <= 956:
                    content = "Kayttaja sisaan"
                elif msg.loop_id >= 961 and msg.loop_id <= 992:
                    content = "Ryhma ohitus paalle"
            elif msg.message_type == 2:
                if msg.loop_id >= 1 and msg.loop_id <= 512:
                    content = "Silmukan kansihalytys"
            elif msg.message_type == 7:
                if msg.loop_id >= 1 and msg.loop_id <= 512:
                    content = "Silmukan ohitus paalle"
            elif msg.message_type == 8:
                if msg.loop_id >= 1 and msg.loop_id <= 512:
                    content = "Silmukan ohitus pois"
            elif msg.message_type == 9:
                if msg.loop_id == 0:
                    content = "Keskuksen linjahalytyksen lepotila"
                elif msg.loop_id >= 1 and msg.loop_id <= 512:
                    content = "Silmukka kiinni (lepo)"
                elif msg.loop_id == 600:
                    content = "Keskus taysvalvontatilaan"
                elif msg.loop_id >= 601 and msg.loop_id <= 632:
                    content = "Ryhma kytketty paalle"
                elif msg.loop_id == 691:
                    content = "Vajaatoiminta (pois)"
                elif msg.loop_id >= 701 and msg.loop_id <= 956:
                    content = "Kayttaja ulos"
                elif msg.loop_id >= 961 and msg.loop_id <= 992:
                    content = "Ryhma ohitus pois"
                # Loop 2000 == HHL-C HB
                elif msg.loop_id == 2000:
                    content = "HHL-C heartbeat, discarding"
                    self.logger.debug(self.name + " - " + content)
                    return
        # Drop service class 91 (= "Tilakysely"), 92 (="Ohjausrele"), 94 (="Ohjauskomento")
        elif msg.service_class == 91:
            self.__log_discarded_msg(msg)
            return
        elif msg.service_class == 92:
            self.__log_discarded_msg(msg)
            return
        elif msg.service_class == 94:
            self.__log_discarded_msg(msg)
            return      

        data = UplinkAlarm(self.number, msg).data
        #data["data"]=content + ": " + data["data"]
        data["data"]=data["data"].replace('\r','')
        self.send_cloud_alarm(data=data, content=content)
        
        # Every received message must be forwarded
        #self.send_cloud_alarm(data=UplinkAlarm(self.number, msg).data, content=content)
        self.logger.debug(self.name + " - " + content)

    def __log_discarded_msg(self, msg):
        if VERBOSE_DEBUG:
            self.logger.debug(self.name + ": on_message_\{prodex,hhl\}(): No message to be forwarded. service_class: {}, system_id {}, msgType {}, loop_id {}"
                .format(msg.service_class, msg.system_id, msg.message_type, msg.loop_id))
        return

    def on_message_prodex(self, msg):
        content = "non-specified"

        if msg.more and VERBOSE_DEBUG:
            self.logger.debug(self.name + ": on_message_prodex(): more bit is set")

        # Parse msg to get msg type code
        # Messages from "Prodex_FIREscape Alerta.doc" (27.7.2015)

        if msg.system_id == 680 and msg.service_class == 10 and msg.message_type in (1,9):
            content = "Palohalytys (ryhma)"
            msg.loop_id = 1
        elif msg.system_id == 681 and msg.service_class == 11 and msg.message_type in (1,9):
            content = "Ennakkohalytys (ryhma)"
            msg.loop_id = 3
            if msg.message_type == 1:
                msg.message_type = 8
        # elif msg.system_id == 682 and msg.service_class == 12 and msg.message_type in (1,9):
        #     content = "Silmukkavika"
        #     msg.loop_id = 2
        #     if msg.message_type == 1:
        #         msg.message_type = 2
        # elif msg.system_id == 684 and msg.service_class == 1 and msg.message_type in (1,9):
        #     content = "Keskuksen vikahalytys"
        #     msg.loop_id = 2
        #     if msg.message_type == 1:
        #         msg.message_type = 2
        # elif msg.system_id == 685 and msg.service_class == 15 and msg.message_type in (1,9):
        #     content = "Laitevika"
        #     msg.loop_id = 2
        #     if msg.message_type == 1:
        #         msg.message_type = 2
        # elif msg.system_id == 687 and msg.service_class == 1 and msg.message_type in (1,9):
        #     content = "Huoltoilmoitus"
        #     msg.loop_id = 4
        #     if msg.message_type == 1:
        #         msg.message_type = 2
        elif msg.system_id == 688 and msg.service_class == 1 and msg.message_type in (1,9):
            content = "Keskuksen linjahalytys"
            msg.loop_id = 0
            if msg.message_type == 1:
                msg.message_type = 3
        elif msg.system_id == 689 and msg.service_class == 1 and msg.message_type in (1,9):
            content = "Palohalytys"
            msg.loop_id = 1
        # Discard and log unnecessary messages
        else:
            self.__log_discarded_msg(msg)
            return

        # Add the content (= error type description) to the front of the error data.
        # Reason is that currently the separate content field in the alarm is not forwarded 
        # from the cloud.

        data = UplinkAlarm(self.number, msg).data
        data["data"]=content + ": " + data["data"]
        data["data"]=data["data"].replace('\r','')
        self.send_cloud_alarm(data=data, content=content)
        
        #self.send_cloud_alarm(data=UplinkAlarm(self.number, msg).data, content=content)


    ''' -------------------------- '''
    ''' Downlink Messages Handlers '''
    ''' -------------------------- '''

    def send_ack(self):
        self.transmit_control_char(ACK)

    def send_nak(self):
        self.transmit_control_char(NAK)

    def send_enq(self):
        self.transmit_control_char(ENQ)
        
    def send_eot(self):
        self.transmit_control_char(EOT)
