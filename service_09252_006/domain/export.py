"""受控批量导出：逐条记录的 Python 授权判断与脱敏（纯领域逻辑）。

安全约束：
- 授权以【单条记录】为单位判断，调用方提供 ``authorizer(user, record)``，
  返回 ``AuthorizationDecision``（也兼容裸 bool）；任何异常一律按拒绝处理，
  绝不“出错即放行”；
- 拒绝记录不进入脱敏阶段——脱敏器只可能看到已授权记录的字段，
  拒绝项的清单行只允许携带 record_id 与稳定分类码（kind/sensitivity
  作为分类元数据保留，与 redact_entry 的口径一致），不含任何字段；
- 授权可给字段白名单，脱敏器输出再按白名单投影一次，防止有缺陷的
  脱敏器把未授权字段带出；
- 拒绝原因码只允许 ``[a-z0-9_]{1,64}``，避免原因码本身成为字段泄露通道。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Collection, Mapping

from .enums import Role, Sensitivity
from .errors import ValidationError
from .fingerprint import canonical_json, digest_bytes
from .models import User

# 稳定的结果/拒绝分类码：可安全写入清单与对外返回，不含字段内容
REASON_OK = "ok"
REASON_DENIED = "denied"
REASON_CROSS_INSTITUTION = "cross_institution"
REASON_SENSITIVE_FORBIDDEN = "sensitive_forbidden"
REASON_AUTHORIZER_ERROR = "authorizer_error"
REASON_SANITIZER_ERROR = "sanitizer_error"
REASON_WRITE_ERROR = "manifest_write_error"

_REASON_RE = re.compile(r"[a-z0-9_]{1,64}")

RecordAuthorizer = Callable[[User, "ExportRecord"], Any]
FieldSanitizer = Callable[[User, "ExportRecord", Mapping[str, Any]], Mapping[str, Any]]


@dataclass(frozen=True)
class ExportRecord:
    """一条待导出记录。

    fields 是原始（未脱敏）字段映射；服务层保证：仅在授权通过后
    才会把 fields 交给脱敏器，拒绝路径永不读取/写出它。
    """

    record_id: str
    institution_id: str
    kind: str
    sensitivity: str = Sensitivity.NORMAL.value
    fields: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason_code: str = REASON_OK
    # None 表示全部字段可进入脱敏器；否则只允许列出的字段离开领域层
    allowed_fields: tuple[str, ...] | None = None

    @staticmethod
    def allow(allowed_fields: tuple[str, ...] | None = None) -> "AuthorizationDecision":
        return AuthorizationDecision(True, REASON_OK, allowed_fields)

    @staticmethod
    def deny(reason_code: str = REASON_DENIED) -> "AuthorizationDecision":
        code = normalize_reason_code(reason_code, REASON_DENIED)
        if code == REASON_OK:
            code = REASON_DENIED  # 拒绝路径绝不能携带“通过”分类码
        return AuthorizationDecision(False, code)


def normalize_reason_code(code: Any, default: str) -> str:
    """把授权方给出的原因码收敛为安全的稳定分类码。"""
    text = str(code or "").strip().lower()
    return text if _REASON_RE.fullmatch(text) else default


def coerce_decision(result: Any) -> AuthorizationDecision:
    """兼容裸 bool 的授权返回；其他类型一律视为授权器故障（失败关闭）。"""
    if isinstance(result, AuthorizationDecision):
        if result.allowed:
            return AuthorizationDecision.allow(result.allowed_fields)
        return AuthorizationDecision.deny(result.reason_code)
    if isinstance(result, bool):
        return AuthorizationDecision.allow() if result else AuthorizationDecision.deny()
    raise TypeError("授权判断必须返回 AuthorizationDecision 或 bool")


def default_authorizer(user: User, record: ExportRecord) -> AuthorizationDecision:
    """默认最小披露策略（机构隔离 + 角色）。

    - 质量权威机构 / 审计：可见全部；
    - 本机构管理员：可见全部；本机构提交人不可见敏感记录；
    - 跨机构记录默认拒绝（需要“仍有效分配”上下文的场景，由调用方
      传入闭包自定义授权器，默认策略不猜测评审关系）。
    """
    if user.has_role(Role.AUDITOR) or user.has_role(Role.QUALITY_AUTHORITY):
        return AuthorizationDecision.allow()

    same_institution = (
        user.institution_id is not None
        and user.institution_id == record.institution_id
    )
    if same_institution:
        if user.has_role(Role.INSTITUTION_ADMIN):
            return AuthorizationDecision.allow()
        if user.has_role(Role.INSTITUTION_SUBMITTER):
            if record.sensitivity == Sensitivity.SENSITIVE.value:
                return AuthorizationDecision.deny(REASON_SENSITIVE_FORBIDDEN)
            return AuthorizationDecision.allow()
        return AuthorizationDecision.deny(REASON_DENIED)

    return AuthorizationDecision.deny(REASON_CROSS_INSTITUTION)


def sanitize_fields(
    user: User,
    record: ExportRecord,
    decision: AuthorizationDecision,
    sanitizer: FieldSanitizer | None,
) -> dict:
    """对已授权记录做脱敏，并按字段白名单做最终投影。

    白名单在自定义脱敏器【之后】再投影一次：即使脱敏器有缺陷，
    未授权字段也不可能离开本函数。不可 JSON 序列化的值在此暴露，
    由服务层记为该条处理失败（不写出任何字段）。
    """
    if sanitizer is None:
        values: Mapping[str, Any] = dict(record.fields)
    else:
        values = dict(sanitizer(user, record, dict(record.fields)))

    if decision.allowed_fields is not None:
        allowed = set(decision.allowed_fields)
        values = {key: value for key, value in values.items() if key in allowed}

    result = dict(values)
    # 提前走一遍确定性编码：拒绝 NaN 与不可序列化对象，保证可写清单
    canonical_json(result)
    return result


def fingerprint_fields(fields: Mapping[str, Any]) -> str:
    """导出字段内容指纹（规范化 JSON 后 SHA-256）。"""
    return digest_bytes(canonical_json(fields))


def make_field_redactor(
    secret_keys: Collection[str], mask: str = "***"
) -> FieldSanitizer:
    """构造一个按字段名遮蔽的脱敏器（键名大小写不敏感）。

    只遮蔽值，键仍保留——导出方能知道“存在该字段”但拿不到内容；
    未列入的字段原样保留。字段级白名单由 AuthorizationDecision
    控制，二者正交。
    """
    secrets = {key.lower() for key in secret_keys}

    def _redact(
        user: User,
        record: "ExportRecord",
        fields: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return {
            key: (mask if key.lower() in secrets else value)
            for key, value in fields.items()
        }

    return _redact


def coerce_record(raw: Any) -> ExportRecord:
    """接受 ExportRecord 或等价映射（HTTP 边界传入 dict）。"""
    if isinstance(raw, ExportRecord):
        return raw
    if not isinstance(raw, Mapping):
        raise ValidationError("待导出记录必须是 ExportRecord 或映射")
    if not str(raw.get("record_id", "")).strip():
        raise ValidationError("record_id 不能为空")
    if not str(raw.get("institution_id", "")).strip():
        raise ValidationError("institution_id 不能为空")
    fields = raw.get("fields") or {}
    if not isinstance(fields, Mapping):
        raise ValidationError("fields 必须是映射")
    return ExportRecord(
        record_id=str(raw["record_id"]),
        institution_id=str(raw["institution_id"]),
        kind=str(raw.get("kind") or "record"),
        sensitivity=str(raw.get("sensitivity") or Sensitivity.NORMAL.value),
        fields=dict(fields),
    )
