import hashlib
import cryptography.fernet
import base64
import datetime

from abc import ABC, abstractmethod
from typing import Optional
from dataclasses import dataclass

@dataclass
class LineageEncryptedData:
    rung: int
    data: bytes

    def __bytes__(self):
        return str(self.rung).encode('utf-8') + b'/' + self.data

    @classmethod
    def from_bytes(cls, x: bytes):
        rung, data = x.split(b'/', 1)
        rung = int(rung)
        return cls(rung=rung, data=data)


class HashLineage(cryptography.fernet.Fernet):
    def __init__(self, key: bytes, max_rung: int):
        key = hashlib.sha256(key).digest()
        key = base64.urlsafe_b64encode(key)

        self.key = key
        self.max_rung = max_rung 
        self.subfernets = {}
        super().__init__(key)

    def _encrypt_from_parts(self, data, time, iv):
        return super()._encrypt_from_parts(data, 0, b'0' * 16)
    
    def _get_child(self, rung: int):
        rungs_down = self.max_rung - rung                   
        assert rungs_down >= 0, f"Cannot ascend a HashLineage from {self.max_rung} to {rung}"
        new_key = self.key
        for _ in range(rungs_down):
            # todo: replace with `rounds` or something
            new_key = hashlib.sha256(new_key).digest()
        if self.subfernets.get(new_key) is None:
            self.subfernets[new_key] = HashLineage(new_key, rung)
        return self.subfernets[new_key]
    
    def sublineage(self, rung):
        return self._get_child(rung)

    def encrypt(self, data: bytes, rung: Optional[int]=None):
        if not rung or rung == self.max_rung:
            return LineageEncryptedData(self.max_rung, super().encrypt(data))
        return self._get_child(rung).encrypt(data)

    def decrypt(self, data: LineageEncryptedData):
        if not data.rung or data.rung == self.max_rung:
            return super().decrypt(data.data)
        return self._get_child(data.rung).decrypt(data)


class AppliedHashLineage(HashLineage, ABC):
    """ A HashLineage variant with a 'translate' method used to accept objects other than integers as rungs if they can be mapped to integers. """

    @classmethod
    @abstractmethod
    def translate(cls, obj):
        pass
   
    @classmethod
    def _translate(cls, obj):
        if obj is None:
            return None
        else:
            return cls.translate(obj)

    def __init__(self, key, max_rung_object):
        return super().__init__(key, self._translate(max_rung_object))

    def encrypt(self, data, rung_object=None):
        return super().encrypt(data, self._translate(rung_object))

    def sublineage(self, rung_object):
        return super()._get_child(self._translate(rung_object))


class DateHashLineage(AppliedHashLineage):
    @classmethod
    def translate(cls, date):
        return datetime.date.toordinal(date)


if __name__ == "__main__":
    now = datetime.datetime.now().date()
    a = DateHashLineage(b'', now)
    b = a.sublineage(now - datetime.timedelta(days=1))
    a_msg = a.encrypt(b'secret', now - datetime.timedelta(days=1))
    b_msg = b.encrypt(b'secret')
    assert a_msg == b_msg, 'consistent encryption across sublineages'
    assert a.decrypt(a_msg) == b.decrypt(b_msg), "each sublineage can decrypt"
    assert a.decrypt(b_msg) == b.decrypt(a_msg), "sublineages may cross-decrypt"
    print("Success")
