import logging
import time
from collections import namedtuple
from functools import lru_cache
from itertools import zip_longest

import serial
from PyCRC.CRC16Kermit import CRC16Kermit


# Translated using Bing Translator from original Russian

logger = logging.getLogger('ccnet')


def grouper(iterable, n, fillvalue=None):
    """
    Collect data into fixed-length chunks or blocks
    grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    """
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


class CashCodeNETCommand:
    """
    CCNET command class. Forms commands, there is a method for validation.
    """
    SYNC = 0x02                                  # always 0x02
    ADR = 0x03                                   # 0x03 is validator

    # CMD:
    ACK = 0x00
    RESET = 0x30
    GET_STATUS = 0x31                            # not tested
    SET_SECURITY = 0x32                          # not tested
    POLL = 0x33
    ENABLE_BILL_TYPES = 0x34
    STACK = 0x35
    RETURN = 0x36                                # not tested
    IDENTIFICATION = 0x37
    HOLD = 0x38                                  # not tested
    SET_BARCODE_PARAMETERS = 0x39                # not tested
    EXTRACT_BARCODE_DATA = 0x3A                  # not tested
    GET_BILL_TABLE = 0x41
    DOWNLOAD = 0x50                              # not tested
    GET_CRC32_OF_THE_CODE = 0x51
    MODULE_DOWNLOAD = 0x52                       # not tested
    VALIDATION_MODULE_IDENTIFICATION = 0x54      # not tested
    GET_CRC16_OF_THE_CODE = 0x56                 # not tested
    GET_CRC32_OF_THE_CODE_WITH_PARAMETRS = 0x57  # not tested
    GET_CRC16_OF_THE_CODE_WITH_PARAMETRS = 0x58  # not tested
    SET_ESCROW_TIMEOUTS = 0x5A                   # not tested
    GET_COUNTER_OF_STACKED_BILL = 0x5B           # not tested
    GET_DATE_OF_THE_RELEASE = 0x5C               # not tested
    REQUEST_STATISTICS = 0x60                    # not tested
    SET_OPTIONS = 0x68                           # not tested
    GET_OPTIONS = 0x69                           # not tested
    DIAGNOSTIC_SETTING = 0xF0                    # not implemented

    @lru_cache()
    def build_message(self, cmd: int, data: tuple = ()):
        """
        Message format:      SYNC    ADR    LNG    CMD    DATA    CRC
            len in bytes:     1       1      1      1     0-250    2

        :param cmd: CMD
        :param data: DATA
        :return: message
        """
        message_body = self.SYNC, self.ADR, self.get_lng(data), cmd, *data
        return message_body + self.get_crc(message_body)

    @classmethod
    def validate_message(cls, message: bytes) -> bool:
        """
        Validation of the message to match the scheme described in the protocol.
        :param message: message in bytes
        :return: message built right - True, Otherwise, - False
        """
        result = message[0] == cls.SYNC and message[1] == cls.ADR and message[2] == len(message) and \
            message[-2:] == bytes(cls.get_crc(tuple(message[:-2])))
        if not result:
            logger.error('Bad message on validate: %s', [hex(i) for i in message])

        return result

    @staticmethod
    def get_lng(message_data: tuple) -> int:
        """
        Long messages. Look build_message / Message format
        :param message_data: data Messages
        :return: the number of bytes of a properly constructed message from the sent message message_data
        """
        return 1 + 1 + 1 + 1 + len(message_data) + 2

    @staticmethod
    def get_crc(message_body: tuple) -> tuple:
        """
        The control amount is 16 bits. Polyn-generated: 0x08408 Example of calculation on page 10
        :param message_body: Message to transmit (without the last two bytes, and believe them)
        :return: two bytes of the calculated amount
        """
        crc_int = CRC16Kermit().calculate(bytes(message_body))
        crc_b = crc_int.to_bytes(2, byteorder='big')
        return tuple(num for num in crc_b)

    @classmethod
    def get_ack(cls):
        """Message: Confirmation"""
        return cls().build_message(cls.ACK)

    @classmethod
    def get_cmd_reset(cls):
        """Message: reset the device, page 38"""
        return cls().build_message(cls.RESET)

    @classmethod
    def get_cmd_get_status(cls):
        """Message: Request for Bill Validator set-up status, page 38"""
        return cls().build_message(cls.GET_STATUS)

    @classmethod
    def get_cmd_set_security(cls, data: tuple):
        """Message: Sets Bill Validator Security Mode, page 38
                :param data: 3 ints 1 byte long each
        """
        return cls().build_message(cls.SET_SECURITY, data)

    @classmethod
    def get_cmd_poll(cls):
        """Message: Device survey, page 39"""
        return cls().build_message(cls.POLL)

    @classmethod
    def get_cmd_get_bill_table(cls):
        """Message: request for accepted banknotes, page 43"""
        return cls().build_message(cls.GET_BILL_TABLE)

    @classmethod
    def get_cmd_enable_bill_types(cls, data: tuple):
        """
        Message: to allow/prohibit the type of banknotes accepted, page 41, possible (those that returned the answer to the
            GET_BILL_TABLE) 3 byte - turn on/off temporary storage of banknotes (escrow) 3 Bytes.

        :param data: 6 ints 1 byte long each
        """
        return cls().build_message(cls.ENABLE_BILL_TYPES, data)

    @classmethod
    def get_cmd_stack(cls):
        """Message: send the banknote to the cassette (with escrow included), page 41"""
        return cls().build_message(cls.STACK)

    @classmethod
    def get_cmd_return(cls):
        """Message: causes the Bill Validator to return bill in escrow position to the customer, page 41"""
        return cls().build_message(cls.RETURN)

    @classmethod
    def get_cmd_identification(cls):
        """Message: Get information about the device, page 42"""
        return cls().build_message(cls.IDENTIFICATION)

    @classmethod
    def get_cmd_hold(cls):
        """Message: holding of Bill Validator in Escrow state, page 42"""
        return cls().build_message(cls.HOLD)

    @classmethod
    def get_cmd_set_barcode_parameters(cls, data: tuple):
        """Message: settings the barcode format and number of characters, page 42

        :param data: 2 ints 1 byte long each
                      byte1 - bar code format. 01H = interleaved 2 of 5.
                      byte2 - number of characters (min 6, max 18).
        
        """
        return cls().build_message(cls.SET_BARCODE_PARAMETERS, data)

    @classmethod
    def get_cmd_extract_barcode_data(cls):
        """Message:  retrieving barcode data if barcode coupon is found. If this command is sent when
           barcode coupon is not found the Bill Validator returns ILLEGAL COMMAND respons, page 43
        """
        return cls().build_message(cls.EXTRACT_BARCODE_DATA)

    @classmethod
    def get_cmd_download(cls):
        """Message: transition to download mode, page 43"""
        return cls().build_message(cls.DOWNLOAD)

    @classmethod
    def get_cmd_module_download(cls):
        """Message: transition to download mode, see CCNET Document 2"""
        return cls().build_message(cls.MODULE_DOWNLOAD)

    @classmethod
    def get_cmd_get_CRC32_of_the_code(cls):
        """Message: get a firmware checklist, page 44"""
        return cls().build_message(cls.GET_CRC32_OF_THE_CODE)

    @classmethod
    def get_cmd_validation_module_identification(cls):
        """Message: Request identification information from banknote validation software module, page 44"""
        return cls().build_message(cls.VALIDATION_MODULE_IDENTIFICATION)

    @classmethod
    def get_cmd_get_CRC16_of_the_code(cls, data: tuple):
        """Message: Request for Bill Validator’s firmware CRC16, page 44

        :param data: seed 2 ints 1 byte long each, MSB first        
        """
        return cls().build_message(cls.GET_CRC16_OF_THE_CODE, data)

    @classmethod
    def get_cmd_get_CRC32_of_the_code_with_parameters(cls, data: tuple):
        """Message:  Request for Bill Validator’s firmware CRC32, page 44

        :param data: 8 ints 1 byte long each
                        byte 1-4 seed, MSB first
                        byte 5-8 start address, MSB first
        """
        return cls().build_message(cls.GET_CRC32_OF_THE_CODE_WITH_PARAMETRS, data)

    @classmethod
    def get_cmd_get_CRC16_of_the_code_with_parameters(cls, data: tuple):
        """Message:  Request for Bill Validator’s firmware CRC16, page 44

        :param data: 6 ints 1 byte long each
                        byte 1-2 seed, MSB first
                        byte 3-6 start address, MSB first
        """
        return cls().build_message(cls.GET_CRC16_OF_THE_CODE_WITH_PARAMETRS, data)

    @classmethod
    def get_cmd_set_escrow_timeouts(cls, data: tuple):
        """Message:  Set escrow timeouts, page 45

        :param data: 8 ints 1 byte long each
                        byte 1-4 bill time-out in msec, MSB first
                        byte 5-8 Voucher time-out in msec, MSB first
        """
        return cls().build_message(cls.SET_ESCROW_TIMEOUTS, data)

    @classmethod
    def get_cmd_get_counter_of_stacked_bills(cls):
        """Message:  Get counter of stacked bills, page 45"""
        return cls().build_message(cls.GET_COUNTER_OF_STACKED_BILL)

    @classmethod
    def get_cmd_get_date_of_the_release(cls):
        """Message:  Get date of the firmware release, page 45"""
        return cls().build_message(cls.GET_DATE_OF_THE_RELEASE)

    @classmethod
    def get_cmd_get_date_of_the_release(cls):
        """Message:  Retrive full information about acceptance performance. See CCNET Document 3 for details"""
        return cls().build_message(cls.REQUEST_STATISTICS)

    @classmethod
    def get_cmd_set_options(cls, data: tuple):
        """Message:  Set various BV options, page 45
        
        :param data: 4 ints 1 byte long each
                        byte 1-4 options
        """
        return cls().build_message(cls.SET_OPTIONS)

    @classmethod
    def get_cmd_get_date_of_the_release(cls):
        """Message:  Get various BV options, page 46"""
        return cls().build_message(cls.GET_OPTIONS)


class CashCodeNETResponse:
    """
    Protocol Response Class CCNET.
    """
    poll_states = {  # page 39
        0x0: 'response_error',
        0x10: 'power_up',
        0x11: 'power_up_with_bill_in_validator',
        0x12: 'power_up_with_bill_in_stacker',
        0x13: 'initialize',
        0x14: 'idling',
        0x15: 'accepting',
        0x17: 'stacking',
        0x18: 'returning',
        0x19: 'disabled',
        0x1A: 'holding',
        0x1B: 'busy',
        0x1C: 'rejecting',
        0x21: 'setting_type_cassette',
        0x25: 'dispensed',
        0x26: 'unloaded',
        0x28: 'invalid_bill_number',
        0x29: 'set_cassette_type',
        0x30: 'invalid_command',
        0x41: 'drop_cassette_full',
        0x42: 'drop_cassette_removed',
        0x43: 'jam_in_acceptor',
        0x44: 'jam_in_stacker',
        0x45: 'cheated',
        0x46: 'pause',
        0x47: 'error',
        0x80: 'escrow',
        0x81: 'stacked',
        0x82: 'returned',
        0x84: 'suspected_bill_detected',
        0x90: 'counterfit_held_in_validator'
    }

    reject_reason = {  # page 39
        0x60: 'Rejecting due to Insertion. Insertion error',
        0x61: 'Rejecting due to Magnetic. Dielectric error',
        0x62: 'Rejecting due to bill Remaining in the head. Bill remains in the head, and new bill is rejected',
        0x63: 'Rejecting due to Multiplying. Compensation error/multiplying factor error',
        0x64: 'Rejecting due to Conveying. Bill transport error',
        0x65: 'Rejecting due to Identification. Identification error',
        0x66: 'Rejecting due to Verification. Verification error',
        0x67: 'Rejecting due to Optic. Optic Sensor error',
        0x68: 'Rejecting due to Inhibit. Returning by inhibit denomination error.',
        0x69: 'Rejecting due to Capacity. Capacitance error',
        0x6A: 'Rejecting due to Operation. Operation error',
        0x6C: 'Rejecting due to Length. Length error',
        0x6D: 'Rejecting due to UV. Banknote UV properties do not meet the predefined criteria',
        0x92: 'Rejecting due to Unrecognized barcode. Bill taken was treated as a barcode but no reliable data can be read from it.',
        0x93: 'Rejecting due to incorrect number of characters in barcode. Barcode data was read (at list partially) but is inconsistent.',
        0x94: 'Rejecting due to unknown barcode start sequence. Barcode was not read as no synchronization was established.',
        0x95: 'Rejecting due to unknown barcode stop sequence. Barcode was read but trailing data is corrupt.',
    }

    response = namedtuple('Response', ['state', 'data', 'reason'])  # it brings back get_poll

    @staticmethod
    def validate_response(response: bytes):
        """
        Validation of message - response from device
        :param response: answer, in bytes
        :return: message built right - True, Otherwise, - False
        """
        if not response:
            return False
        return CashCodeNETCommand.validate_message(response)

    @classmethod
    def get_bill_table(cls, response: bytes):
        """
        Parsit's response GET BILL TABLE (0x41, Page. 43)
        :param response: answer, in bytes
        :return: list of dictionaries with the value of the accepted bill and its country code. List length 24, when included/
            turning off the types of accepted, when specifying which banknote is identified, the index is transferred from that list
        """
        if not cls.validate_response(response):
            logger.error('Bad response in get_bill_table')
            return {}

        response_body = response[3:-2]
        result = []
        for word in grouper(response_body, 5):
            first_digit = word[0]
            proceeding_zeros = word[4]
            country_code = word[1:4]

            result.append({
                'amount': first_digit * (10 ** proceeding_zeros),
                'code': ''.join(map(chr, country_code)),
            })
        return result

    @classmethod
    def get_poll(cls, response: bytes):
        """
         Parsit's response POLL (0x33, Page. 39)
         :param response: answer, in bytes
         :return: self.response:
            state: State of the device. Uses self.poll_states
            data: body (part of the data-) messages
            reason: reason to move, if there is one. Uses self.reject_reason
         """
        if not cls.validate_response(response):
            response_body = b'\x00'
        else:
            response_body = response[3:-2]
        return cls.response(
            cls.poll_states[response_body[0]],
            [i for i in response_body],
            cls.reject_reason.get(response_body[-1]),
        )


class CashCodeMSM:
    """Team-pool class and protocol responses"""
    command_class = CashCodeNETCommand
    response_class = CashCodeNETResponse

    def __init__(self, port, baud_rate=9600, timeout=1, enabled_bill=()):
        """
        :param enabled_bill: banknotes, such as banknotes: (100, 200, 1000)
        :param port: COM port to which the device is connected
        :param timeout: Time to wait for a response from the device

        Connectivity options (Page 8):
            Speed: 9600/19200, selected on the device,
            Start Bit: 1,
            Word size: 8 Bit, 0 bit is transmitted first,
            Parity: None,
            stop bit: 1.
        """
        self.serial = serial.Serial(port=port, baudrate=baud_rate, timeout=timeout, writeTimeout=timeout,
                                    stopbits=serial.STOPBITS_ONE, bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE)

        self.enabled_bill = enabled_bill
        self.bill_table = {}

        self.send_cmd(self.command_class.get_cmd_reset())
        self.bill_table = {}

    def poll(self):
        return self.response_class.get_poll(self.send_cmd(self.command_class.get_cmd_poll()))

    def get_bill_table(self):
        return self.send_cmd(self.command_class.get_cmd_get_bill_table())

    def enable_bill_types(self, country_code):
        """
        Include to pay, page 20
        self.enabled_bill: list of banknote values, in rubles. For example: (50, 100, 500) Notes outside this list are not accepted, even if they are recognized.
        self.bill_table: list of bills from the validator firmware. Length Strictly 24!
        """
        self.bill_table = self.response_class.get_bill_table(self.get_bill_table())

        enable_types = 0
        for bit_num in range(3 * 8):
            current_type = self.bill_table[bit_num]
            current_type_code = current_type.get('code')
            current_type_amount = current_type.get('amount')
            if current_type_code == country_code and current_type_amount in self.enabled_bill:
                enable_types += 1 << bit_num

        bills_enable = [int(i) for i in enable_types.to_bytes(3, byteorder='big')]
        escrow_enable = [int(i) for i in enable_types.to_bytes(3, byteorder='big')]     # enable escrow for all bill types
        
        # escrow_enable = [0x00, 0x00, 0x00]  # I turn off the escrow, the bills go straight into the cassette
    
        result = bills_enable + escrow_enable

        return self.send_cmd(self.command_class.get_cmd_enable_bill_types(tuple(result)))

    def disable_bill_types(self):
        """Transfer the validator to the state of 'disabled' (red diode burns, degy does not accept)"""
        return self.send_cmd(self.command_class.get_cmd_enable_bill_types((0x00, 0x00, 0x00, 0x00, 0x00, 0x00)))

    def stack(self):
        """Send the bill to the cassette"""
        return self.send_cmd(self.command_class.get_cmd_stack())

    def reset(self):
        """Reset. The device will complete the operation and restart"""
        return self.send_cmd(self.command_class.get_cmd_reset(), confirmation=False)

    def get_crc32_of_the_code(self):
        return self.send_cmd(self.command_class.get_cmd_get_CRC32_of_the_code(), confirmation=False)

    def send_cmd(self, command: tuple, confirmation=True) -> bytes:
        """
        Sending commands to your device
        :param command: Command to send will be sent as is, modifications/checks will not be carried out
        :param confirmation: Confirmation of the response, True - yes, False - no
        :return: device response bytes
        """
        self._send_command(command)
        response = self._get_response()

        if confirmation:
            self._send_command(self.command_class.get_ack())

        return response

    def _send_command(self, command: tuple) -> int:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug('Send command: %s', [hex(i) for i in command])
        return self.serial.write(command)

    def _get_response(self) -> bytes:
        """
        Get an answer, first I try to get the first three bytes, in the third byte is the number of bytes in
            message, then receive a specified number without three, which has already been received
        :return: Device response
        """
        first_three = self.serial.read(3)
        if not first_three:  # didn't answer
            return first_three

        other = self.serial.read(first_three[2] - 3)
        response = first_three + other

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug('Got response: %s', [hex(i) for i in response])
        return response


class MsmValidator:
    """
    Class to work with validator by protocols CCNET.
    It has two methods to control:
        get_bills - to get money.
            Return: False - Validator is already active, otherwise True
        turn_off - Put to a waiting state
            Return: amount received while the validator has been active

    Feedback on callbacks that are called at the events:
        callback_get_bills_done - received the amount at least get_bills.
            Arguments:
                Amount received
        callback_timeout - get_bills was called, but during the timeout time stated, the amount requested did not gain
            Arguments:
                amount received while the validator has been active
        callback_bill_stacked - the banknote was in the cassette
            Arguments:
                denomination banknotes
        callback_cassette_removed - dismantled the cassette. It will be called once
            No argument.

    For normal operation, you will need to call the tick method at intervals of 0.3-0.5c (not strictly).
    """
    def __init__(
            self,
            callback_get_bills_done=print,
            callback_timeout=print,
            callback_bill_stacked=print,
            callback_cassette_removed=print,
            callback_device_removed=print,
            country_code='VNM',
            *args, **kwargs):

        self.validator = CashCodeMSM(*args, **kwargs)

        self.cassette_removed = False
        self.active = False

        self.on_time = 0
        self.timeout = 0

        self.amount = 0  # amount to receive
        self.current_amount = 0  # how much scored in the current session
        
        self.country_code = country_code

        self.callback_get_bills_done = callback_get_bills_done
        self.callback_timeout = callback_timeout
        self.callback_bill_stacked = callback_bill_stacked
        self.callback_cassette_removed = callback_cassette_removed
        self.callback_device_removed = callback_device_removed

    def tick(self):
        """
        The basic method. Asks for validator status, throws out the appropriate method.
        """
        if self.active:
            if self.on_time + self.timeout < time.time():
                logger.warning('Turn off on timeout')
                self.callback_timeout(self.turn_off())

        response = self.validator.poll()
        current_func = getattr(self, 'on_{}'.format(response.state))
        current_func(response)

        time.sleep(0.5)

    # management functions, call out out to start/stop the process of withdrawing money from the population

    def get_bills(self, amount: int, timeout: int = 120):
        """
        To get the money. The receiver's cash goes into active condition (the bill receiver burns green), stays in it
        until it receives the specified amount or exceeds the timeout.

        :param amount: amount to receive
        :param timeout: for how long to try to get
        :return: False if you're already in the process of receiving, otherwise True
        """
        logger.info('Get bills, amount: %s, timeout: %s', amount, timeout)
        if self.active:
            return False

        self.amount = amount
        self.on_time = time.time()
        self.timeout = timeout
        self.active = True

        return True

    def turn_off(self, force=False):
        """
        Stop the process of getting money, internal variables into default states.
        Goes into a waiting state (the bill lights red).
        :param force: True - rigidly resetite, validator will stop internal processes.
        :return: The amount I managed to get before the stop.
        """
        result = self.current_amount

        self.active = False
        self.amount = 0
        self.on_time = 0
        self.timeout = 0
        self.current_amount = 0

        if force:
            self.validator.reset()
        else:
            self.validator.disable_bill_types()
        return result

    # methods called by the machine, depending on the validator state
    def on_power_up(self, response):
        """Included"""
        self.validator.reset()

    def on_initialize(self, response):
        """just waiting to get initiated"""
        pass

    def on_disabled(self, response):
        """Off, turn it on!"""
        if self.cassette_removed:
            self.cassette_removed = False
        if self.active:
            self.validator.enable_bill_types(country_code=self.country_code)

    def on_idling(self, response):
        """waiting for money"""
        pass

    def on_accepting(self, response):
        """waiting for validation"""
        pass

    def on_escrow(self, response):
        """the banknote is defined, pushing it into the cassette"""
        self.validator.stack()
        logger.info('Accept bill: %s', self.validator.bill_table[response.data[-1]])

    def on_stacking(self, response):
        """I'm waiting for the banknote to hit the cassette """
        pass

    def on_stacked(self, response):
        """banknote in cassette """
        bill_value = self.validator.bill_table[response.data[-1]]['amount']

        logger.info('Get bill: %s', bill_value)
        self.callback_bill_stacked(bill_value)

        self.current_amount += bill_value

        if self.amount <= self.current_amount:
            self.callback_get_bills_done(self.turn_off())

    def on_returned(self, response):
        """banknote returned """
        logger.info('Returned bill: %s', self.validator.bill_table[response.data[-1]])

    def on_rejecting(self, response):
        """the banknote did not pass validation """
        logger.warning('Rejected. Reason: %s', response.reason)

    def on_drop_cassette_removed(self, response):
        """the cassette was pulled out """
        if not self.cassette_removed:
            logger.warning('Cassette removed')
            self.callback_cassette_removed()
            self.cassette_removed = True

    def on_response_error(self, response):
        """Error in the validator response (or none at all) """
        logger.warning('Bad response from device: %s', response.data)
        if response.data == [0]:
            logger.critical('Device unplugged')
            self.callback_device_removed()
