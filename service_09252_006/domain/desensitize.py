"""导出脱敏：纯函数，对授权通过的记录内容做不可逆遮蔽。

受控批量导出只允许“脱敏后的内容”离开系统：
- 邮箱：保留首字符，其余与域名一并遮蔽（``z***@***``）；
- 手机号（中国大陆 11 位）：保留前 3 后 4（``138****1234``）；
- 身份证号（18 位）：保留前 4 后 2；
- 银行卡等长数字串（16–19 位）：仅保留后 4 位。

所有函数确定性、无副作用，供应用服务逐条调用，也便于离线复算核对。
"""
from __future__ import annotations

import re

_EMAIL = re.compile(r"([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+")
_MOBILE = re.compile(r"(?<!\d)(1[3-9]\d)\d{4}(\d{4})(?!\d)")
_ID_CARD = re.compile(r"(?<![0-9A-Za-z])(\d{4})\d{12}(\d[0-9Xx])(?![0-9A-Za-z])")
_BANK_CARD = re.compile(r"(?<!\d)\d{12,15}(\d{4})(?!\d)")


def mask_emails(text: str) -> str:
    return _EMAIL.sub(lambda m: m.group(1) + "***@***", text)


def mask_mobiles(text: str) -> str:
    return _MOBILE.sub(lambda m: m.group(1) + "****" + m.group(2), text)


def mask_id_cards(text: str) -> str:
    return _ID_CARD.sub(lambda m: m.group(1) + "************" + m.group(2), text)


def mask_bank_cards(text: str) -> str:
    return _BANK_CARD.sub(lambda m: "************" + m.group(1), text)


def desensitize_text(text: str) -> str:
    """对导出文本依次应用全部遮蔽规则。"""
    text = mask_emails(text)
    text = mask_id_cards(text)
    text = mask_bank_cards(text)
    text = mask_mobiles(text)
    return text


def desensitize_content(data: bytes) -> str:
    """把材料字节解码为文本并脱敏；无法解码的字节做替换处理。"""
    return desensitize_text(data.decode("utf-8", errors="replace"))
