"""受控批量导出服务：逐条授权、逐条落清单、单条失败不阻塞。

核心不变量：
- 每条记录独立执行 Python 授权判断（domain.disclosure.entry_denial_reason），
  与包视图/下载共用同一份最小披露规则；
- 每条记录在自己的事务内处理并写入 SQLite 清单（export_items）——
  某条被拒或处理异常只影响该条，其他允许条目照常完成导出；
- 被拒/失败的清单条目只保留 entry_id 与原因码，不写入任何记录字段
  （kind/title/sha256/content 一律为空），清单本身不泄露未授权内容；
- 授权通过的条目导出前必须脱敏（domain.desensitize），原始字节不出库；
- 批次收尾时对整份清单做指纹（export_manifest_fingerprint），
  导出结果可离线对账。
"""
from __future__ import annotations

from ..domain.desensitize import desensitize_content
from ..domain.disclosure import entry_denial_reason
from ..domain.enums import ExportBatchStatus, ExportItemStatus, PackageStatus, Role
from ..domain.errors import (
    ConflictError,
    DomainError,
    NotFoundError,
    PermissionDeniedError,
)
from ..domain.fingerprint import export_manifest_fingerprint
from ..domain.models import (
    ExportBatch,
    ExportItem,
    PackageEntry,
    ReviewPackage,
    User,
)
from .base import Service, require_user


class ExportService(Service):
    def export_package(
        self,
        actor: User,
        *,
        package_id: str,
        idempotency_key: str | None = None,
    ) -> dict:
        """对已封存的评审包执行受控批量导出。

        任何能查看该包的用户都可发起；能看到哪些记录由逐条授权判断
        决定——无权记录只会以“denied + 原因码”出现在清单中。
        """
        require_user(actor)
        package = self.repo.get_package(package_id)
        if package is None:
            raise NotFoundError("评审包不存在")
        if package.status == PackageStatus.DRAFT.value:
            raise ConflictError(
                "评审包尚未封存，清单未固定，不能导出",
                details={"package_id": package_id, "status": package.status},
            )
        self._require_package_relationship(actor, package)

        if idempotency_key is not None:
            prior = self.repo.get_idempotent_result(idempotency_key)
            if prior is not None:
                prior["replayed"] = True
                return prior

        export_id = self.ids.new_id("exp")
        with self.repo.transaction():
            self.repo.insert_export_batch(
                ExportBatch(
                    export_id=export_id,
                    package_id=package.package_id,
                    institution_id=package.institution_id,
                    requested_by=actor.user_id,
                    status=ExportBatchStatus.RUNNING.value,
                    total=len(package.entries),
                    exported=0,
                    denied=0,
                    errors=0,
                    manifest_fingerprint=None,
                    created_at=self.clock.now_iso(),
                    completed_at=None,
                )
            )
            self.audit(
                actor.user_id, "export.started",
                package_id=package.package_id,
                institution_id=package.institution_id,
                detail={"export_id": export_id, "total": len(package.entries)},
            )

        # 逐条处理：每条独立事务，被拒/异常都不阻塞后续条目
        active = {
            r.package_id
            for r in self.repo.list_active_requests_by_reviewer(actor.user_id)
        }
        for entry in package.entries:
            self._process_entry(actor, package, entry, active, export_id)

        with self.repo.transaction():
            items = self.repo.list_export_items(export_id)
            exported = sum(1 for i in items if i.status == ExportItemStatus.EXPORTED.value)
            denied = sum(1 for i in items if i.status == ExportItemStatus.DENIED.value)
            errors = sum(1 for i in items if i.status == ExportItemStatus.ERROR.value)
            completed_at = self.clock.now_iso()
            fingerprint = export_manifest_fingerprint(
                export_id,
                package.package_id,
                [
                    {
                        "entry_id": i.entry_id,
                        "status": i.status,
                        "reason": i.reason,
                        "sha256": i.sha256,
                        "content_text": i.content_text,
                    }
                    for i in items
                ],
                completed_at,
            )
            self.repo.finalize_export_batch(
                export_id,
                status=ExportBatchStatus.COMPLETED.value,
                exported=exported,
                denied=denied,
                errors=errors,
                manifest_fingerprint=fingerprint,
                completed_at=completed_at,
            )
            self.audit(
                actor.user_id, "export.completed",
                package_id=package.package_id,
                institution_id=package.institution_id,
                detail={
                    "export_id": export_id,
                    "exported": exported,
                    "denied": denied,
                    "errors": errors,
                    "manifest_fingerprint": fingerprint,
                },
            )
            result = {
                "export_id": export_id,
                "package_id": package.package_id,
                "status": ExportBatchStatus.COMPLETED.value,
                "total": len(package.entries),
                "exported": exported,
                "denied": denied,
                "errors": errors,
                "manifest_fingerprint": fingerprint,
                "created_at": self.repo.get_export_batch(export_id).created_at,
                "completed_at": completed_at,
                "replayed": False,
            }
            if idempotency_key is not None:
                self.repo.save_idempotent_result(idempotency_key, dict(result))
            return result

    def get_export(self, actor: User, export_id: str) -> dict:
        """查看导出清单。仅发起人、本机构管理员、权威机构、审计可见。"""
        require_user(actor)
        batch = self.repo.get_export_batch(export_id)
        if batch is None:
            raise NotFoundError("导出批次不存在")
        if not (
            actor.user_id == batch.requested_by
            or actor.has_role(Role.AUDITOR)
            or actor.has_role(Role.QUALITY_AUTHORITY)
            or (
                actor.institution_id is not None
                and actor.institution_id == batch.institution_id
                and actor.has_role(Role.INSTITUTION_ADMIN)
            )
        ):
            raise PermissionDeniedError("无权查看该导出清单")
        items = self.repo.list_export_items(export_id)
        return {
            "export_id": batch.export_id,
            "package_id": batch.package_id,
            "institution_id": batch.institution_id,
            "requested_by": batch.requested_by,
            "status": batch.status,
            "total": batch.total,
            "exported": batch.exported,
            "denied": batch.denied,
            "errors": batch.errors,
            "manifest_fingerprint": batch.manifest_fingerprint,
            "created_at": batch.created_at,
            "completed_at": batch.completed_at,
            "items": [
                {
                    "entry_id": i.entry_id,
                    "status": i.status,
                    "kind": i.kind,
                    "sensitivity": i.sensitivity,
                    "title": i.title,
                    "sha256": i.sha256,
                    "size": i.size,
                    "media_type": i.media_type,
                    "content_text": i.content_text,
                    "reason": i.reason,
                    "decided_at": i.decided_at,
                }
                for i in items
            ],
        }

    # ------------------------------------------------------------- 逐条处理
    def _process_entry(
        self,
        actor: User,
        package: ReviewPackage,
        entry: PackageEntry,
        active_package_ids: set[str],
        export_id: str,
    ) -> None:
        """处置一条记录：授权判断 -> 脱敏导出 / 拒记 / 记异常。

        无论结果如何都写入清单；单条异常被捕获并记为 error，
        绝不向上抛出阻塞其他条目。
        """
        try:
            with self.repo.transaction():
                reason = entry_denial_reason(actor, active_package_ids, entry, package)
                if reason is not None:
                    # 被拒：只记 entry_id 与原因码，不写任何记录字段
                    self.repo.insert_export_item(
                        ExportItem(
                            export_id=export_id,
                            entry_id=entry.entry_id,
                            status=ExportItemStatus.DENIED.value,
                            decided_at=self.clock.now_iso(),
                            reason=reason,
                        )
                    )
                    return
                item = self._build_exported_item(export_id, entry)
                self.repo.insert_export_item(item)
        except Exception as exc:  # noqa: BLE001 —— 单条失败必须被包容
            code = exc.code if isinstance(exc, DomainError) else "processing_error"
            with self.repo.transaction():
                self.repo.insert_export_item(
                    ExportItem(
                        export_id=export_id,
                        entry_id=entry.entry_id,
                        status=ExportItemStatus.ERROR.value,
                        decided_at=self.clock.now_iso(),
                        reason=code,
                    )
                )

    def _build_exported_item(self, export_id: str, entry: PackageEntry) -> ExportItem:
        """授权通过：取出记录字段，内容脱敏后写入清单。"""
        material = self.repo.get_material(entry.material_id)
        version = self.repo.get_version(entry.version_id)
        blob = self.repo.get_blob(entry.sha256)
        if material is None or version is None or blob is None:
            raise NotFoundError(
                "记录内容缺失，无法导出", details={"entry_id": entry.entry_id}
            )
        return ExportItem(
            export_id=export_id,
            entry_id=entry.entry_id,
            status=ExportItemStatus.EXPORTED.value,
            decided_at=self.clock.now_iso(),
            kind=entry.kind,
            sensitivity=entry.sensitivity,
            title=material.title,
            sha256=entry.sha256,
            size=version.size,
            media_type=version.media_type,
            content_text=desensitize_content(blob.data),
        )

    def _require_package_relationship(
        self, actor: User, package: ReviewPackage
    ) -> None:
        """与包视图一致的包级门禁：与该包毫无关系的外部用户直接拒绝。"""
        if (
            actor.institution_id is not None
            and actor.institution_id == package.institution_id
        ):
            return
        if actor.has_role(Role.QUALITY_AUTHORITY) or actor.has_role(Role.AUDITOR):
            return
        is_assigned = actor.has_role(Role.REVIEWER) and any(
            r.reviewer_id == actor.user_id
            for r in self.repo.list_requests_by_package(package.package_id)
        )
        if is_assigned:
            return
        raise PermissionDeniedError("不能导出其他机构评审包")
