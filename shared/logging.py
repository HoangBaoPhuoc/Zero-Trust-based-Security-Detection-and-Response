# ZTLab - shared logging
# Source: IMPLEMENTATION.md §6.1
# See MAP.md §9 for context and edit guidance

import logging

class ZTLabLogger:
    def __init__(self, service: str, cloud: str):
        self.service = service
        self.cloud = cloud
        self.logger = logging.getLogger(service)

    def info(self, msg: str):
        self.logger.info(msg)

# TODO: populate structured JSON logger from IMPLEMENTATION.md §6.1
