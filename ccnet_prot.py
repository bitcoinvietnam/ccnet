from collections import namedtuple
from functools import lru_cache

from PyCRC.CRC16Kermit import CRC16Kermit
from itertools import zip_longest
import serial
import time
import logging

logger = logging.getLogger('app')


def grouper(iterable, n, fillvalue=None):
    """
    Collect data into fixed-length chunks or blocks
    grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    """
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


class CashCodeNETCommand:
    """
    Класс команд протокола CCNET. Формирует команды, есть метод для валидации.
    """
    SYNC = 0x02
    ADR = 0x03

    # CMD:
    ACK = 0x00
    RESET = 0x30
    POLL = 0x33
    ENABLE_BILL_TYPES = 0x34
    STACK = 0x35
    IDENTIFICATION = 0x37
    GET_BILL_TABLE = 0x41
    GET_CRC32 = 0x51
    POWER_RECOVERY = 0x66

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
        Валидация сообщения на соответствие схемы описанной в протоколе.
        :param message: сообщение в байтах
        :return: сообщение построено верно - True, в противном случае - False
        """
        result = message[0] == cls.SYNC and message[1] == cls.ADR and message[2] == len(message) and \
               message[-2:] == bytes(cls.get_crc(tuple(message[:-2])))
        if not result:
            logger.error('Bad message on validate: %s', [hex(i) for i in message])

        return result

    @staticmethod
    def get_lng(message_data: tuple) -> int:
        """
        Длинна сообщения. Смотри build_message / Message format
        :param message_data: data сообщения
        :return: количество байт правильно построенного сообщения с переданной message_data
        """
        return 1 + 1 + 1 + 1 + len(message_data) + 2

    @staticmethod
    def get_crc(message_body: tuple) -> tuple:
        """
        Контрольная сумма 16 бит. Порождаемый полином: 0x08408 Пример расчета на стр. 10
        :param message_body: Сообщение для передачи (без последних двух байт, их и считаем)
        :return: два байта расчитанной суммы
        """
        crc_int = CRC16Kermit().calculate(bytes(message_body))
        crc_b = crc_int.to_bytes(2, byteorder='big')
        return tuple(num for num in crc_b)

    @classmethod
    def get_ack(cls):
        """Сообщение: подтверждение"""
        return cls().build_message(cls.ACK)

    @classmethod
    def get_cmd_reset(cls):
        """Сообщение: сброс устройства, стр. 17"""
        return cls().build_message(cls.RESET)

    @classmethod
    def get_cmd_poll(cls):
        """Сообщение: опрос устройства, стр. 18"""
        return cls().build_message(cls.POLL)

    @classmethod
    def get_cmd_get_bill_table(cls):
        """Сообщение: запрос принимаемых банкнот, стр. 26"""
        return cls().build_message(cls.GET_BILL_TABLE)

    @classmethod
    def get_cmd_enable_bill_types(cls, data: tuple):
        """
        Сообщение: разрешить/запретить тип принимаемых банкнот, стр. 20 из возможных (тех что вернул ответ на
            GET_BILL_TABLE) 3 байта + включить/выключить временное хранение банкнот (escrow) 3 байта.

        :param data: кортеж из 6 интов 1 байт длиной каждый
        """
        return cls().build_message(cls.ENABLE_BILL_TYPES, data)

    @classmethod
    def get_cmd_stack(cls):
        """Сообщение: отправить банкноту в кассету (при включенном escrow), стр. 21"""
        return cls().build_message(cls.STACK)

    @classmethod
    def get_cmd_power_recovery(cls):
        """Сообщение: включись, стр. 26"""
        return cls().build_message(cls.POWER_RECOVERY)

    @classmethod
    def get_cmd_get_CRC_32(cls):
        """Сообщение: получить контрольную сумму прошивки, стр. 25"""
        return cls().build_message(cls.GET_CRC32)

    @classmethod
    def get_cmd_identification(cls):
        """Сообщение: получить сведения об устройстве, стр. 21"""
        return cls().build_message(cls.IDENTIFICATION)


class CashCodeNETResponse:
    """
    Класс ответов протокола CCNET.
    """
    poll_states = {  # стр. 19
        0x0: 'response_error',
        0x10: 'power_up',
        0x13: 'initialize',
        0x14: 'idling',
        0x15: 'accepting',
        0x17: 'stacking',
        0x18: 'returning',
        0x19: 'disabled',
        0x1A: 'holding',
        0x1B: 'busy',
        0x1C: 'rejecting',
        0x1D: 'dispensing',
        0x1E: 'unloading',
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
        0x47: 'error',
        0x80: 'escrow',
        0x81: 'stacked',
        0x82: 'returned'
    }

    reject_reason = {  # стр.19
        0x60: 'Rejecting due to Insertion. Insertion error',
        0x61: 'Rejecting due to Magnetic. Magnetic error',
        0x62: 'Rejecting due to bill Remaining in the head. Bill remains in the head, and new bill is rejected',
        0x63: 'Rejecting due to Multiplying. Compensation error/multiplying factor error',
        0x64: 'Rejecting due to Conveying. Conveying error',
        0x65: 'Rejecting due to Identification1. Identification error',
        0x66: 'Rejecting due to Verification. Verification error',
        0x67: 'Rejecting due to Optic. Optic error',
        0x68: 'Rejecting due to Inhibit. Returning by inhibit denomination error.',
        0x6C: 'Rejecting due to Length. Length error',
    }

    response = namedtuple('Response', ['state', 'data', 'reason'])  # это возвращает get_poll

    @staticmethod
    def validate_response(response: bytes):
        """
        Валидация сообщения - ответа от устройства
        :param response: ответ, в байтах
        :return: сообщение построено верно - True, в противном случае - False
        """
        if not response:
            return False
        return CashCodeNETCommand.validate_message(response)

    @classmethod
    def get_bill_table(cls, response: bytes):
        """
        Парсит ответ на GET BILL TABLE (0x41, стр. 26)
        :param response: ответ, в байтах
        :return: список словарей с значением принимаемой купюры и ее кодом страны. Длина списка 24, при включении/
            выключении принимаемых типов, при указании какая банкнота идентифицирована передается индекс из этого списка
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
         Парсит ответ на POLL (0x33, стр. 18)
         :param response: ответ, в байтах
         :return: self.response:
            state: состояние в котором находится устройство. Использует self.poll_states
            data: body (часть содержащая данные) сообщения
            reason: причина перехода, если есть. Использует self.reject_reason
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


class CashCodeSM:
    """Класс объединяющий команды и ответы протокола"""
    command_class = CashCodeNETCommand
    response_class = CashCodeNETResponse

    def __init__(self, enabled_bill=(), port='/dev/ttyUSB0', baud_rate=9600, timeout=1):
        """
        :param enabled_bill: принимаемые банкноты, например: (100, 200, 1000)
        :param port: COM port к которому подключено устройство
        :param timeout: время ожидания ответа от устройства

        Параметры подключения (стр.9):
            скорость: 9600/19200, выбирается на устройстве,
            стартовый бит: 1,
            размер слова: 8 бит, 0 бит передается первым,
            четность: не проверяется,
            стоп бит: 1.
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

    def enable_bill_types(self, code='RUS'):
        """
        Включить к оплате, стр. 20
        self.enabled_bill: список значений купюр, в рублях. Например: (50, 100, 500) Купюры вне этого списка приниматься
            не будут, даже если будут распознаны.
        self.bill_table: список купюр из прошивки валидатора. Длина строго 24!
        """
        self.bill_table = self.response_class.get_bill_table(self.get_bill_table())
        escrow_enable = [0x00, 0x00, 0x00]  # выключаю escrow, купюры сразу идут в кассету

        enable_types = 0
        for bit_num in range(3 * 8):
            current_type = self.bill_table[bit_num]
            current_type_code = current_type.get('code')
            current_type_amount = current_type.get('amount')
            if current_type_code == code and current_type_amount in self.enabled_bill:
                enable_types += 1 << bit_num

        result = [int(i) for i in enable_types.to_bytes(3, byteorder='big')] + escrow_enable

        return self.send_cmd(self.command_class.get_cmd_enable_bill_types(tuple(result)))

    def disable_bill_types(self):
        """Перевести валидатор в состояние 'disabled' (горит красный диод, деьги не принимает)"""
        return self.send_cmd(self.command_class.get_cmd_enable_bill_types((0x00, 0x00, 0x00, 0x00, 0x00, 0x00)))

    def stack(self):
        """Отправить купюру в кассету"""
        return self.send_cmd(self.command_class.get_cmd_stack())

    def reset(self):
        """Reset. Устройство завершит выполняемую операцию и перезагрузится"""
        return self.send_cmd(self.command_class.get_cmd_reset(), confirmation=False)

    def power_recovery(self):
        return self.send_cmd(self.command_class.get_cmd_power_recovery(), confirmation=False)

    def get_crc32(self):
        return self.send_cmd(self.command_class.get_cmd_get_CRC_32(), confirmation=False)

    def send_cmd(self, command: tuple, confirmation=True) -> bytes:
        """
        Отправка команды на устройство
        :param command: команда для отправки; будет отправлена как есть, модификаций/проверок проводится не будет
        :param confirmation: подтверждение принятия ответа, True - нужно, False - нет
        :return: байты ответа устройства
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
        Получить ответ, сначала пытаюсь получить первые три байта, в третьем байте находится количество байт в
            сообщении, затем получаю указанное количество без трех, который уже получены
        :return: ответ устройства
        """
        first_three = self.serial.read(3)
        if not first_three:  # не ответил
            return first_three

        other = self.serial.read(first_three[2] - 3)
        response = first_three + other

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug('Get response: %s', [hex(i) for i in response])
        return response


class SmValidator:
    """
    Класс для работы с валидатором по протоколы CCNET.
    Имеет два метода для управления:
        get_bills - для получения денег.
            Return: False - валидатор уже активен, иначе True
        turn_off - перевод в состояние ожидания
            Return: сумма, полученная пока валидатор был активен

    Обратная связь на колбэках, которые вызываются при наступлении следующих событий:
        callback_get_bills_done - получена сумма не меньше запрашиваемой в get_bills.
            Аргументы:
                полученная сумма
        callback_timeout - был вызван get_bills, но в течении времени указанной в timeout запрошенная сумма не набралась
            Аргументы:
                сумма, полученная пока валидатор был активен
        callback_bill_stacked - банкнота попала в кассету
            Аргументы:
                номинал банкноты
        callback_cassette_removed - демонтирована кассета. Вызовется один раз
            Без аргументов.

    Для нормальной работы требйутся вызывать метод tick с интервалом 0,3-0,5с (не строго).
    """
    def __init__(
            self,
            callback_get_bills_done=print,
            callback_timeout=print,
            callback_bill_stacked=print,
            callback_cassette_removed=print,
            callback_device_removed=print,
            *args, **kwargs):

        self.validator = CashCodeSM(*args, **kwargs)

        self.cassette_removed = False
        self.active = False

        self.on_time = 0
        self.timeout = 0

        self.amount = 0  # сумма к получению
        self.current_amount = 0  # сколько набрал в текущем сеансе

        self.callback_get_bills_done = callback_get_bills_done
        self.callback_timeout = callback_timeout
        self.callback_bill_stacked = callback_bill_stacked
        self.callback_cassette_removed = callback_cassette_removed
        self.callback_device_removed = callback_device_removed

    def tick(self):
        """
        Основной метод. Запрашивает состояние валидатора, вызвает соответствующий ему метод.
        """
        if self.active:
            if self.on_time + self.timeout < time.time():
                logger.warning('Turn off on timeout')
                self.callback_timeout(self.turn_off())

        response = self.validator.poll()
        current_func = getattr(self, 'on_{}'.format(response.state))
        current_func(response)

        time.sleep(0.5)

    # управляющие функции, вызывать из вне для начала/остановки процесса изъятия денег у населения

    def get_bills(self, amount: int, timeout: int = 120):
        """
        Полуить денег. Кэш приемник переходит в активное состояние (купюроприемник горит зеленым), пребывает в нем
        пока не получит указанную сумму или не превысит таймаут.

        :param amount: сумма к получению
        :param timeout: в течении какого времени пытаться получить
        :return: False если уже в процессе получения, иначе True
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
        Остановить процесс получения денег, внутренние переменные в дефолтные состояния.
        Переходит в состояние ожидания (купюроприемник горит красным).
        :param force: True - жестко ресетит, валидатор остановит внутренние процессы.
        :return: Сумму, которую успел получить до остановки.
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

    # методы вызываемые автоматом, в зависимости от состояния валидатора
    def on_power_up(self, response):
        """включается"""
        self.validator.reset()

    def on_initialize(self, response):
        """просто жду когда проинициализируется"""
        pass

    def on_disabled(self, response):
        """выключен, включаем!"""
        if self.cassette_removed:
            self.cassette_removed = False
        if self.active:
            self.validator.enable_bill_types()

    def on_idling(self, response):
        """жду денег"""
        pass

    def on_accepting(self, response):
        """жду валидацию"""
        pass

    def on_escrow(self, response):
        """банкнота определена, толкаем в кассету"""
        self.validator.stack()
        logger.info('Accept bill: %s', self.validator.bill_table[response.data[-1]])

    def on_stacking(self, response):
        """жду когда банкнота попадет в кассету"""
        pass

    def on_stacked(self, response):
        """банкнота в кассете"""
        bill_value = self.validator.bill_table[response.data[-1]]['amount']

        logger.info('Get bill: %s', bill_value)
        self.callback_bill_stacked(bill_value)

        self.current_amount += bill_value

        if self.amount <= self.current_amount:
            self.callback_get_bills_done(self.turn_off())

    def on_returned(self, response):
        """банкнота возвращена"""
        logger.info('Returned bill: %s', self.validator.bill_table[response.data[-1]])

    def on_rejecting(self, response):
        """банкнота не прошла валидацию"""
        logger.warning('Rejected. Reason: %s', response.reason)

    def on_drop_cassette_removed(self, response):
        """была вытащенная кассета"""
        if not self.cassette_removed:
            logger.warning('Cassette removed')
            self.callback_cassette_removed()
            self.cassette_removed = True

    def on_response_error(self, response):
        """Ошибка в ответе валидатора (или его нет вообще)"""
        logger.warning('Bad response from device: %s', response.data)
        if response.data == [0]:
            logger.critical('Device unplugged')
            self.callback_device_removed()
