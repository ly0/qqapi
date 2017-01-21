import uuid


class QRCodeManager:
    def __init__(self):
        self.qrcode_id = uuid.uuid4().hex