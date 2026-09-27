"""受控批量导出：逐条授权、拒绝项不泄露字段、单条失败不阻塞、脱敏与清单指纹。"""
import json
import sqlite3
import unittest

from service_09252_006.domain.enums import (
    ExportBatchStatus,
    ExportItemStatus,
    MaterialKind,
    Role,
    Sensitivity,
)
from service_09252_006.domain.errors import ConflictError, PermissionDeniedError
from service_09252_006.domain.fingerprint import export_manifest_fingerprint
from tests.flow import seal_new_package, upload_material
from tests.support import Harness

SENSITIVE_CONTENT = "敏感反馈：企业要求匿名"


class ExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.submitter = self.h.user("sub-a", Role.INSTITUTION_SUBMITTER)
        self.admin_b = self.h.user(
            "admin-b", Role.INSTITUTION_ADMIN, institution_id="inst-b"
        )
        self.authority = self.h.user(
            "auth", Role.QUALITY_AUTHORITY, institution_id=None
        )
        self.auditor = self.h.user("aud", Role.AUDITOR, institution_id=None)
        self.reviewer = self.h.user(
            "rev-1", Role.REVIEWER, institution_id="inst-ext"
        )
        self.sealed = seal_new_package(self.h, self.admin)
        self.pid = self.sealed.package_id
        # items[0] 普通大纲，items[1] 敏感企业反馈
        self.sensitive_version = self.sealed.items[1].version["version_id"]
        self.sensitive_sha = self.sealed.items[1].version["sha256"].split(":", 1)[1]

    def tearDown(self) -> None:
        self.h.close()

    def _export(self, actor, **kwargs):
        return self.h.ctx.exports.export_package(actor, package_id=self.pid, **kwargs)

    def _items(self, export_id):
        return self.h.ctx.exports.get_export(self.auditor, export_id)["items"]

    def _denied_item(self, export_id):
        return next(
            i for i in self._items(export_id)
            if i["status"] == ExportItemStatus.DENIED.value
        )

    # -------------------------------------------------- 拒绝项不泄露字段
    def test_denied_item_does_not_leak_fields(self) -> None:
        result = self._export(self.submitter)
        self.assertEqual(result["status"], ExportBatchStatus.COMPLETED.value)
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["exported"], 1)
        self.assertEqual(result["denied"], 1)
        self.assertEqual(result["errors"], 0)

        denied = self._denied_item(result["export_id"])
        self.assertEqual(denied["reason"], "sensitive_feedback_restricted")
        # 除 entry_id/status/reason/decided_at 外，所有记录字段必须为空
        for field in (
            "kind", "sensitivity", "title", "sha256",
            "size", "media_type", "content_text",
        ):
            self.assertIsNone(denied[field], f"拒绝项泄露了字段 {field}")

        # 敏感内容与其指纹不得出现在清单的任何角落
        manifest_json = json.dumps(
            self.h.ctx.exports.get_export(self.auditor, result["export_id"]),
            ensure_ascii=False,
        )
        self.assertNotIn(SENSITIVE_CONTENT, manifest_json)
        self.assertNotIn(self.sensitive_sha, manifest_json)
        self.assertNotIn(self.sensitive_version, manifest_json)

        # 直接查 SQLite 清单行：拒绝项在库里同样没有字段
        row = self.h.repo._conn.execute(
            "SELECT * FROM export_items WHERE export_id = ? AND status = 'denied'",
            (result["export_id"],),
        ).fetchone()
        self.assertIsNotNone(row)
        for column in (
            "kind", "sensitivity", "title", "sha256",
            "size", "media_type", "content_text",
        ):
            self.assertIsNone(row[column], f"SQLite 清单泄露了列 {column}")

    # -------------------------------------------------- 拒绝不阻塞其他条目
    def test_denial_does_not_block_allowed_entries(self) -> None:
        result = self._export(self.submitter)
        exported = next(
            i for i in self._items(result["export_id"])
            if i["status"] == ExportItemStatus.EXPORTED.value
        )
        # 允许条目完整导出（含脱敏后内容与字段）
        self.assertEqual(exported["kind"], MaterialKind.SYLLABUS.value)
        self.assertEqual(exported["title"], "材料")
        self.assertIsNotNone(exported["sha256"])
        self.assertEqual(exported["content_text"], "大纲 v1")
        # 批次正常收尾：计数对账平衡
        self.assertEqual(
            result["total"],
            result["exported"] + result["denied"] + result["errors"],
        )

    def test_single_record_error_does_not_block_others(self) -> None:
        # 直接删掉一条记录的内容字节，模拟单条数据损坏
        conn = sqlite3.connect(self.h.db_path)
        try:
            conn.execute("DELETE FROM blobs WHERE sha256 = ?", (self.sensitive_sha,))
            conn.commit()
        finally:
            conn.close()

        result = self._export(self.admin)
        self.assertEqual(result["status"], ExportBatchStatus.COMPLETED.value)
        self.assertEqual(result["exported"], 1)
        self.assertEqual(result["errors"], 1)
        self.assertEqual(result["denied"], 0)

        items = self._items(result["export_id"])
        error = next(
            i for i in items if i["status"] == ExportItemStatus.ERROR.value
        )
        self.assertEqual(error["reason"], "not_found")
        # 失败条目同样不保留任何字段
        self.assertIsNone(error["sha256"])
        self.assertIsNone(error["content_text"])
        # 其他条目照常完成导出
        exported = next(
            i for i in items if i["status"] == ExportItemStatus.EXPORTED.value
        )
        self.assertEqual(exported["content_text"], "大纲 v1")

    # ------------------------------------------------------------- 脱敏
    def test_exported_content_is_desensitized(self) -> None:
        pii = (
            "联系人张三，邮箱 zhangsan@example.com，手机 13812345678，"
            "身份证 110101199003077758，卡号 6222020200112233445"
        )
        item = upload_material(
            self.h, self.admin,
            kind=MaterialKind.ASSESSMENT.value,
            data=pii.encode("utf-8"),
            title="考核材料",
        )
        pkg = seal_new_package(self.h, self.admin, items=[item], title="脱敏包")
        result = self.h.ctx.exports.export_package(
            self.admin, package_id=pkg.package_id
        )
        self.assertEqual(result["exported"], 1)
        content = self._items(result["export_id"])[0]["content_text"]
        self.assertIn("联系人张三", content)
        self.assertIn("z***@***", content)
        self.assertIn("138****5678", content)
        self.assertIn("1101************58", content)
        self.assertIn("************3445", content)
        for raw in (
            "zhangsan@example.com", "13812345678",
            "110101199003077758", "6222020200112233445",
        ):
            self.assertNotIn(raw, content)

    # ------------------------------------------------- 权限变化即时生效
    def test_reviewer_export_follows_active_assignment(self) -> None:
        req = self.h.ctx.reviews.assign_reviewer(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
        )
        # 有效分配中：敏感条目可导出
        result1 = self._export(self.reviewer)
        self.assertEqual(result1["exported"], 2)
        self.assertEqual(result1["denied"], 0)

        # 取消分配后：逐条判断即时失权，全部拒绝，但导出本身仍完成
        self.h.ctx.reviews.cancel_request(
            self.authority, request_id=req["request_id"], reason="改派"
        )
        result2 = self._export(self.reviewer)
        self.assertEqual(result2["exported"], 0)
        self.assertEqual(result2["denied"], 2)
        for item in self._items(result2["export_id"]):
            self.assertEqual(item["reason"], "no_active_assignment")
            self.assertIsNone(item["sha256"])
            self.assertIsNone(item["content_text"])

    # ------------------------------------------------------------- 门禁
    def test_draft_package_cannot_be_exported(self) -> None:
        pkg = self.h.ctx.packages.create_package(self.admin, title="草稿包")
        with self.assertRaises(ConflictError):
            self.h.ctx.exports.export_package(
                self.admin, package_id=pkg["package_id"]
            )

    def test_unrelated_institution_cannot_export(self) -> None:
        with self.assertRaises(PermissionDeniedError):
            self._export(self.admin_b)

    def test_get_export_manifest_permissions(self) -> None:
        result = self._export(self.submitter)
        export_id = result["export_id"]
        # 发起人、审计、权威机构、本机构管理员可见
        for actor in (self.submitter, self.auditor, self.authority, self.admin):
            view = self.h.ctx.exports.get_export(actor, export_id)
            self.assertEqual(view["export_id"], export_id)
        # 外机构用户不可见
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.exports.get_export(self.admin_b, export_id)

    # --------------------------------------------------------- 幂等与对账
    def test_export_is_idempotent_by_key(self) -> None:
        r1 = self._export(self.admin, idempotency_key="exp-key-1")
        r2 = self._export(self.admin, idempotency_key="exp-key-1")
        self.assertEqual(r1["export_id"], r2["export_id"])
        self.assertFalse(r1["replayed"])
        self.assertTrue(r2["replayed"])
        row = self.h.repo._conn.execute(
            "SELECT COUNT(*) AS c FROM export_batches"
        ).fetchone()
        self.assertEqual(row["c"], 1)

    def test_manifest_fingerprint_reconciles(self) -> None:
        result = self._export(self.admin)
        view = self.h.ctx.exports.get_export(self.auditor, result["export_id"])
        # 用清单内容离线重算，指纹必须一致（任何一条被改动都会失配）
        recomputed = export_manifest_fingerprint(
            view["export_id"],
            view["package_id"],
            view["items"],
            view["completed_at"],
        )
        self.assertEqual(recomputed, view["manifest_fingerprint"])

        tampered = [dict(i) for i in view["items"]]
        tampered[0]["status"] = ExportItemStatus.DENIED.value
        forged = export_manifest_fingerprint(
            view["export_id"], view["package_id"], tampered, view["completed_at"]
        )
        self.assertNotEqual(forged, view["manifest_fingerprint"])


if __name__ == "__main__":
    unittest.main()
