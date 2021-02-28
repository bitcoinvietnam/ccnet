#!/usr/bin/env python3
import time
import logging

logger = logging.getLogger('ccnet')
logger.setLevel(logging.DEBUG)
cons_handler = logging.StreamHandler()
cons_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s  %(message)s')
cons_handler.setFormatter(formatter)
logger.addHandler(cons_handler)

from ccnet_prot import SmValidator


if __name__ == '__main__':

    logger.info('Starting')
    device = SmValidator(port='/dev/ttyS7', baud_rate=9600, timeout=1, country_code='VNM', enabled_bill=(500000, 200000, 100000, 50000, 20000, 10000, 5000, 2000, 1000))
    device.get_bills(100000)
    logger.info('Init device done')

    try:
        while True:
            device.tick()
            time.sleep(0.5)
    except KeyboardInterrupt:
        logger.warning('Stopping')