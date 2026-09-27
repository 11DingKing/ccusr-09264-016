"""受控批量导出服务：逐条授权、逐条脱敏、逐条独立提交 SQLite 清单。

设计要点（对应受控导出的两个安全要求）：

1. **逐条授权，失败关闭。** 每条记录单独调用注入的 Python 授权器
   ``authorizer(user, record)``；授权器抛异常或返回非法类型一律按拒绝
   处理。被拒记录不会进入脱敏阶段，返回与清单中都只有 record_id 与
   稳定分类码（kind/sensitivity 为分类元数据），绝不包含字段值。

2. **单条失败不阻塞其他条目。** 批次行先在自己的事务里提交；之后
   每条记录的结果在【独立事务】里写入清单并立即提交——某条写入
   失败只回滚该条，后续记录继续。最后单独事务汇总计数。因此调用方
   不能把整个批次包在一个外层事务里（仓储事务可重入，会退化为单事务）。
"""
from __future__ import annotations

import json
from typing import Any, Iterable

from ..domain.enums import ExportItemStatus, Role
from ..domain.export import (
    REASON_AUTHORIZER_ERROR,
    REASON_OK,
    REASON_SANITIZER_ERROR,
    REASON_WRITE_ERROR,
    FieldSanitizer,
    RecordAuthorizer,
    coerce_decision,
    coerce_record,
    default_authorizer,
    fingerprint_fields,
    sanitize_fields,
)
from ..domain.errors import NotFoundError, PermissionDeniedError, ValidationError
from ..domain.fingerprint import canonical_json
from ..domain.models import ExportBatch, ExportItem, User
from .base import Service, require_user

_EXPORTED = ExportItemStatus.EXPORTED.value
_DENIED = ExportItemStatus.DENIED.value
_ERROR = ExportItemStatus.ERROR.value


class ExportService(Service):
    def __init__(
        self,
        repo,
        clock,
        ids,
        *,
        authorizer: RecordAuthorizer | None = None,
        sanitizer: FieldSanitizer | None = None,
    ) -> None:
        super().__init__(repo, clock, ids)
        # 逐条记录的 Python 授权判断；默认走机构隔离 + 角色的最小披露策略，
        # 调用方可注入自定义授权器（如需要评审分配上下文）。
        self.authorizer: RecordAuthorizer = authorizer or default_authorizer
        # 可选脱敏器；只可能收到已授权记录的字段。
        self.sanitizer = sanitizer

    # ------------------------------------------------------------ 主用例
    def export_batch(
        self,
        actor: User,
        records: Iterable[Any],
        *,
        purpose: str = "",
        batch_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        require_user(actor)
        # 入站校验在任何写入之前完成：格式错误整体 422，不产生半成品批次。
        normalized = [coerce_record(r) for r in records]
        if not normalized:
            raise ValidationError("批量导出至少需要一条记录")
        seen: set[str] = set()
        for record in normalized:
            if record.record_id in seen:
                raise ValidationError(
                    "同批导出中 record_id 不能重复",
                    details={"record_id": record.record_id},
                )
            seen.add(record.record_id)

        # 幂等回放：同键直接返回首次结果，不重新授权、不重复导出。
        if idempotency_key is not None:
            with self.repo.transaction():
                prior = self.repo.get_idempotent_result(idempotency_key)
            if prior is not None:
                prior["replayed"] = True
                return prior

        bid = batch_id or self.ids.new_id("exp")
        created_at = self.clock.now_iso()
        batch = ExportBatch(
            batch_id=bid,
            requested_by=actor.user_id,
            purpose=purpose.strip(),
            created_at=created_at,
            completed_at=None,
            total=len(normalized),
            exported=0,
            denied=0,
            errored=0,
        )
        # 事务 1：批次行独立落盘并提交，之后逐条处理不受单条失败牵连。
        with self.repo.transaction():
            if self.repo.get_export_batch(bid) is not None:
                raise ValidationError(
                    "导出批次已存在", details={"batch_id": bid}
                )
            self.repo.insert_export_batch(batch)
            self.audit(
                actor.user_id, "export.started",
                institution_id=actor.institution_id,
                detail={"batch_id": bid, "total": len(normalized),
                        "purpose": purpose.strip()},
            )

        # 每条记录独立事务提交。
        for seq, record in enumerate(normalized, start=1):
            self._process_one(actor, bid, seq, record)

        result = self._finalize(actor, bid, idempotency_key)
        result.setdefault("replayed", False)
        return result

    # --------------------------------------------------------- 单条处理
    def _process_one(
        self, actor: User, batch_id: str, seq: int, record
    ) -> None:
        """授权 → 脱敏 → 独立事务写清单；任何失败都不外抛、不阻塞下一条。"""
        decided_at = self.clock.now_iso()
        status, reason_code, fields_json, digest = self._decide(actor, record)
        item = ExportItem(
            item_id=self.ids.new_id("exi"),
            batch_id=batch_id,
            record_id=record.record_id,
            seq=seq,
            kind=record.kind,
            sensitivity=record.sensitivity,
            status=status,
            reason_code=reason_code,
            fields_json=fields_json,
            sha256=digest,
            decided_at=decided_at,
        )
        if not self._persist_item(actor, item):
            # 首次写入失败：降级为 error 行再试一次，仍失败则只影响本计数。
            fallback = ExportItem(
                item_id=self.ids.new_id("exi"),
                batch_id=batch_id,
                record_id=record.record_id,
                seq=seq,
                kind=record.kind,
                sensitivity=record.sensitivity,
                status=_ERROR,
                reason_code=REASON_WRITE_ERROR,
                fields_json=None,
                sha256=None,
                decided_at=decided_at,
            )
            self._persist_item(actor, fallback)

    def _decide(
        self, actor: User, record
    ) -> tuple[str, str, str | None, str | None]:
        """返回 (status, reason_code, fields_json, sha256)。

        除“授权通过且脱敏成功”外，其余路径 fields/sha256 全部为 None，
        从结果构造上保证被拒/失败记录的字段无处可写。
        """
        try:
            decision = coerce_decision(self.authorizer(actor, record))
        except Exception:
            return _DENIED, REASON_AUTHORIZER_ERROR, None, None

        if not decision.allowed:
            return _DENIED, decision.reason_code, None, None

        try:
            safe_fields = sanitize_fields(actor, record, decision, self.sanitizer)
        except Exception:
            # 脱敏器故障或字段不可序列化：不输出任何字段
            return _ERROR, REASON_SANITIZER_ERROR, None, None

        return (
            _EXPORTED,
            REASON_OK,
            canonical_json(safe_fields).decode("utf-8"),
            fingerprint_fields(safe_fields),
        )

    def _persist_item(self, actor: User, item: ExportItem) -> bool:
        try:
            with self.repo.transaction():
                self.repo.insert_export_item(item)
                if item.status == _EXPORTED:
                    action, detail = "export.item_exported", {
                        "batch_id": item.batch_id,
                        "record_id": item.record_id,
                        "sha256": item.sha256,  # 审计只留指纹，不留字段内容
                    }
                else:
                    action = (
                        "export.item_denied"
                        if item.status == _DENIED
                        else "export.item_failed"
                    )
                    detail = {
                        "batch_id": item.batch_id,
                        "record_id": item.record_id,
                        "reason_code": item.reason_code,
                    }
                self.audit(
                    actor.user_id, action,
                    institution_id=actor.institution_id, detail=detail,
                )
            return True
        except Exception:
            return False

    # ------------------------------------------------------------- 汇总
    def _finalize(
        self, actor: User, batch_id: str, idempotency_key: str | None
    ) -> dict:
        with self.repo.transaction():
            batch = self.repo.get_export_batch(batch_id)
            items = batch.items
            exported = sum(1 for i in items if i.status == _EXPORTED)
            denied = sum(1 for i in items if i.status == _DENIED)
            # 连 error 行都没能落盘的记录也必须计入失败，保证三数之和=total
            persisted = {i.seq for i in items}
            missing = batch.total - len(persisted)
            errored = sum(1 for i in items if i.status == _ERROR) + missing
            completed_at = self.clock.now_iso()
            self.repo.update_export_batch_counts(
                batch_id,
                exported=exported,
                denied=denied,
                errored=errored,
                completed_at=completed_at,
            )
            self.audit(
                actor.user_id, "export.completed",
                institution_id=actor.institution_id,
                detail={"batch_id": batch_id, "total": batch.total,
                        "exported": exported, "denied": denied,
                        "errored": errored},
            )
            result = self._batch_dict(self.repo.get_export_batch(batch_id))
            if idempotency_key is not None:
                self.repo.save_idempotent_result(idempotency_key, result)
        return result

    # ------------------------------------------------------------- 视图
    def get_batch(self, actor: User, batch_id: str) -> dict:
        require_user(actor)
        batch = self.repo.get_export_batch(batch_id)
        if batch is None:
            raise NotFoundError("导出批次不存在")
        if (
            batch.requested_by != actor.user_id
            and not actor.has_role(Role.AUDITOR)
            and not actor.has_role(Role.QUALITY_AUTHORITY)
        ):
            raise PermissionDeniedError("只能查看本人发起的导出清单")
        return self._batch_dict(batch)

    @staticmethod
    def _item_dict(item: ExportItem) -> dict:
        base = {
            "item_id": item.item_id,
            "record_id": item.record_id,
            "seq": item.seq,
            "kind": item.kind,
            "sensitivity": item.sensitivity,
            "status": item.status,
            "reason_code": item.reason_code,
            "decided_at": item.decided_at,
        }
        if item.status == _EXPORTED:
            base["fields"] = json.loads(item.fields_json)
            base["sha256"] = item.sha256
            base["redacted"] = False
        else:
            # 拒绝/失败：显式占位，不附带任何字段或内容指纹
            base["fields"] = None
            base["sha256"] = None
            base["redacted"] = True
        return base

    def _batch_dict(self, batch: ExportBatch | None) -> dict:
        if batch is None:
            raise NotFoundError("导出批次不存在")
        return {
            "batch_id": batch.batch_id,
            "requested_by": batch.requested_by,
            "purpose": batch.purpose,
            "created_at": batch.created_at,
            "completed_at": batch.completed_at,
            "total": batch.total,
            "exported": batch.exported,
            "denied": batch.denied,
            "errored": batch.errored,
            "items": [self._item_dict(i) for i in batch.items],
        }
