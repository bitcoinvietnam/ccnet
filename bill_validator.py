#!/usr/bin/env python3
import time
import logging
import sys

logging.basicConfig(filename="bill_validator.log",
                    filemode='a',
                    format='%(asctime)s %(levelname)s %(name)s  %(message)s',
                    datefmt='%H:%M:%S',
                    level=logging.DEBUG)
logger = logging.getLogger('ccnet')

from ccnet_prot import MsmValidator


if __name__ == '__main__':

    requested_amount = int(sys.argv[1])
    logger.info("requested_amount: " + str(requested_amount))

    logger.info('Starting')
    device = MsmValidator(port='/dev/ttyS7', baud_rate=9600, timeout=1, country_code='VNM', enabled_bill=(500000, 200000, 100000, 50000, 20000, 10000, 5000, 2000, 1000))
    device.get_bills(requested_amount)
    logger.info('Init device done')

    try:
        while not device.process_completed:
            device.tick()
            time.sleep(0.5)
    except KeyboardInterrupt:
        logger.warning('Stopping')
