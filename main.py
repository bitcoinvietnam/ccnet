#!/bin/env python3
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
    device = SmValidator(port='/dev/ttyS7')
    device.get_bills(500)
    logger.info('Init device done')

    try:
        while True:
            device.tick()
            time.sleep(0.5)
    except KeyboardInterrupt:
        logger.warning('Stopping')