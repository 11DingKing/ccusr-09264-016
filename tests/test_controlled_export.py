"""受控批量导出：逐条授权、拒绝项不泄露字段且不阻塞其他项。

覆盖：
- 默认最小披露授权（机构隔离 / 敏感反馈对提交人遮蔽 / 审计全见）；
- 拒绝项与失败项的返回值和 SQLite 清单行都不含任何字段或内容指纹；
- 授权器/脱敏器异常按拒绝/失败处理（失败关闭），不阻塞后续记录；
- 脱敏器字段遮蔽与授权字段白名单双重收敛；
- 单条清单写入失败时独立回滚，批次内其他条目照常提交；
- 幂等键回放；HTTP 端到端。
"""
from __future__ import annotations

import json
import sqlite3
import unittest
import urllib.error
import urllib.request

from service_09252_006.api.http_api import HttpApiServer
from service_09252_006.application.export_service import ExportService
from service_09252_006.domain.enums import Role, Sensitivity
from service_09252_006.domain.errors import PermissionDeniedError, ValidationError
from service_09252_006.domain.export import (
    REASON_AUTHORIZER_ERROR,
    REASON_CROSS_INSTITUTION,
    REASON_SENSITIVE_FORBIDDEN,
    REASON_WRITE_ERROR,
    AuthorizationDecision,
    ExportRecord,
    make_field_redactor,
)
from tests.support import Harness

SECRET = "匿名企业X-机密联系方式"
PHONE = "13900000000"


def rec(record_id, institution="inst-a", *, sensitive=False, **fields):
    return ExportRecord(
        record_id=record_id,
        institution_id=institution,
        kind="enterprise_feedback",
        sensitivity=(
            Sensitivity.SENSITIVE.value if sensitive else Sensitivity.NORMAL.value
        ),
        fields={"company": SECRET, "contact_phone": PHONE,
                "score": 91, **fields},
    )


class _OnceFailRepo:
    """代理仓储：对指定 seq 的清单行仅首次写入抛错，模拟单条提交失败。"""

    def __init__(self, inner, fail_seq: int) -> None:
        self._inner = inner
        self._fail_seq = fail_seq
        self._failed = False

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def insert_export_item(self, item) -> None:
        if item.seq == self._fail_seq and not self._failed:
            self._failed = True
            raise RuntimeError("模拟该条清单写入失败")
        return self._inner.insert_export_item(item)


class ControlledExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.submitter = self.h.user("sub-a", Role.INSTITUTION_SUBMITTER)
        self.admin_b = self.h.user(
            "admin-b", Role.INSTITUTION_ADMIN, institution_id="inst-b"
        )
        self.auditor = self.h.user("aud", Role.AUDITOR, institution_id=None)

    def tearDown(self) -> None:
        self.h.close()

    def _by_id(self, result, record_id):
        return next(i for i in result["items"] if i["record_id"] == record_id)

    # ------------------------------------------------- 核心安全要求
    def test_denied_record_leaks_no_fields_and_does_not_block_others(self) -> None:
        records = [
            rec("r-ok"),                                  # 本机构普通：放行
            rec("r-sensitive", sensitive=True),           # 本机构敏感：提交人拒绝
            rec("r-foreign", institution="inst-b"),       # 跨机构：拒绝
        ]
        result = self.h.ctx.exports.export_batch(
            self.submitter, records, purpose="学期评审导出"
        )

        self.assertEqual(result["total"], 3)
        self.assertEqual(result["exported"], 1)
        self.assertEqual(result["denied"], 2)
        self.assertEqual(result["errored"], 0)

        allowed = self._by_id(result, "r-ok")
        self.assertEqual(allowed["status"], "exported")
        self.assertEqual(allowed["fields"]["company"], SECRET)
        self.assertTrue(allowed["sha256"])

        for rid, code in (
            ("r-sensitive", REASON_SENSITIVE_FORBIDDEN),
            ("r-foreign", REASON_CROSS_INSTITUTION),
        ):
            denied = self._by_id(result, rid)
            self.assertEqual(denied["status"], "denied")
            self.assertEqual(denied["reason_code"], code)
            self.assertIsNone(denied["fields"])
            self.assertIsNone(denied["sha256"])
            self.assertTrue(denied["redacted"])

        # 三条记录都携带同样的机密字段；序列化后的整体结果里，
        # 机密值只允许来自放行那一条（company 一次 + phone 一次）。
        blob = json.dumps(result, ensure_ascii=False)
        self.assertEqual(blob.count(SECRET), 1)
        self.assertEqual(blob.count(PHONE), 1)

    def test_denied_rows_in_sqlite_have_null_fields(self) -> None:
        result = self.h.ctx.exports.export_batch(
            self.submitter,
            [rec("r-ok"), rec("r-foreign", institution="inst-b")],
        )
        bid = result["batch_id"]
        conn = sqlite3.connect(self.h.db_path)
        try:
            rows = conn.execute(
                "SELECT record_id, status, reason_code, fields_json, sha256"
                " FROM export_items WHERE batch_id = ? ORDER BY seq",
                (bid,),
            ).fetchall()
            leaked = conn.execute(
                "SELECT COUNT(*) FROM export_items"
                " WHERE status != 'exported'"
                " AND (fields_json IS NOT NULL OR sha256 IS NOT NULL)"
            ).fetchone()[0]
            secret_hits = conn.execute(
                "SELECT COUNT(*) tofts FROM ("
                "  SELECT COALESCE(fields_json,'') AS tofts FROM export_items"
                ") WHERE tofts LIKE '%' || ? || '%'",
                (SECRET,),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual([r[0] for r in rows], ["r-ok", "r-foreign"])
        self.assertEqual(rows[1][1], "denied")
        self.assertEqual(rows[1][2], REASON_CROSS_INSTITUTION)
        self.assertIsNone(rows[1][3])  # fields_json 为 NULL
        self.assertIsNone(rows[1][4])  # sha256 为 NULL
        self.assertEqual(leaked, 0)    # 全表不变量：非放行行无任何字段
        self.assertEqual(secret_hits, 1)  # 机密值只出现在放行行

    def test_admin_exports_own_institution_and_auditor_exports_all(self) -> None:
        own = [rec("a"), rec("b", sensitive=True)]
        result = self.h.ctx.exports.export_batch(self.admin, own)
        self.assertEqual(result["exported"], 2)
        self.assertEqual(result["denied"], 0)

        everywhere = own + [rec("c", institution="inst-b")]
        result = self.h.ctx.exports.export_batch(self.auditor, everywhere)
        self.assertEqual(result["exported"], 3)

    # ------------------------------------------------- 失败关闭
    def test_authorizer_exception_is_denied_and_keeps_going(self) -> None:
        def authorizer(user, record):
            if record.record_id == "boom":
                raise RuntimeError("授权器内部故障")
            if record.record_id == "no":
                return False
            return True

        svc = ExportService(self.h.repo, self.h.clock, self.h.ids,
                            authorizer=authorizer)
        result = svc.export_batch(
            self.admin, [rec("yes"), rec("boom"), rec("no"), rec("yes2")]
        )
        self.assertEqual(result["exported"], 2)
        self.assertEqual(result["denied"], 2)
        boom = self._by_id(result, "boom")
        self.assertEqual(boom["status"], "denied")
        self.assertEqual(boom["reason_code"], REASON_AUTHORIZER_ERROR)
        self.assertIsNone(boom["fields"])
        # 后面的记录仍被处理（没有因异常中断）
        self.assertEqual(self._by_id(result, "yes2")["status"], "exported")

    def test_invalid_authorizer_return_fails_closed(self) -> None:
        svc = ExportService(
            self.h.repo, self.h.clock, self.h.ids,
            authorizer=lambda u, r: "maybe",  # 非 bool/Decision
        )
        result = svc.export_batch(self.admin, [rec("r1"), rec("r2")])
        self.assertEqual(result["denied"], 2)
        self.assertTrue(all(i["reason_code"] == REASON_AUTHORIZER_ERROR
                            for i in result["items"]))

    def test_sanitizer_exception_emits_error_row_without_fields(self) -> None:
        def broken_sanitizer(user, record, fields):
            if record.record_id == "bad":
                raise RuntimeError("脱敏器故障")
            return fields

        svc = ExportService(self.h.repo, self.h.clock, self.h.ids,
                            sanitizer=broken_sanitizer)
        result = svc.export_batch(self.admin, [rec("good"), rec("bad")])
        self.assertEqual(result["exported"], 1)
        self.assertEqual(result["errored"], 1)
        bad = self._by_id(result, "bad")
        self.assertEqual(bad["status"], "error")
        self.assertIsNone(bad["fields"])
        self.assertIsNone(bad["sha256"])

    # ------------------------------------------------- 脱敏与白名单
    def test_sanitizer_masks_secret_fields(self) -> None:
        svc = ExportService(
            self.h.repo, self.h.clock, self.h.ids,
            sanitizer=make_field_redactor(["contact_phone", "COMPANY"]),
        )
        result = svc.export_batch(self.admin, [rec("r1")])
        item = self._by_id(result, "r1")
        self.assertEqual(item["fields"]["contact_phone"], "***")
        self.assertEqual(item["fields"]["company"], "***")  # 大小写不敏感
        self.assertEqual(item["fields"]["score"], 91)
        # 指纹基于脱敏后的内容，反推不出原值
        self.assertNotIn(PHONE, item["sha256"])

    def test_field_allowlist_is_enforced_after_sanitizer(self) -> None:
        # 脱敏器“不小心”多带出一个未授权字段，白名单仍要裁掉
        def leaky_sanitizer(user, record, fields):
            fields["extra_secret"] = "不应出现"
            return fields

        def allowlist_authorizer(user, record):
            return AuthorizationDecision.allow(allowed_fields=("score",))

        svc = ExportService(
            self.h.repo, self.h.clock, self.h.ids,
            authorizer=allowlist_authorizer, sanitizer=leaky_sanitizer,
        )
        result = svc.export_batch(self.admin, [rec("r1")])
        fields = self._by_id(result, "r1")["fields"]
        self.assertEqual(fields, {"score": 91})

    # ------------------------------------------------- 独立提交
    def test_one_item_write_failure_does_not_roll_back_others(self) -> None:
        flaky = _OnceFailRepo(self.h.ctx.repo, fail_seq=2)
        svc = ExportService(flaky, self.h.clock, self.h.ids)
        result = svc.export_batch(
            self.admin, [rec("r1"), rec("r2"), rec("r3")]
        )
        self.assertEqual(result["exported"], 2)
        self.assertEqual(result["errored"], 1)
        mid = self._by_id(result, "r2")
        self.assertEqual(mid["status"], "error")
        self.assertEqual(mid["reason_code"], REASON_WRITE_ERROR)
        self.assertIsNone(mid["fields"])
        # 其余两条独立事务已落盘
        self.assertEqual(self._by_id(result, "r1")["status"], "exported")
        self.assertEqual(self._by_id(result, "r3")["status"], "exported")

        persisted = self.h.ctx.exports.get_batch(self.admin,
                                                 result["batch_id"])
        self.assertEqual(persisted["exported"], 2)
        self.assertEqual(persisted["errored"], 1)

    # ------------------------------------------------- 幂等与校验
    def test_idempotency_key_replays_first_result(self) -> None:
        r1 = self.h.ctx.exports.export_batch(
            self.submitter, [rec("a"), rec("b", institution="inst-b")],
            purpose="p", idempotency_key="export-1",
        )
        r2 = self.h.ctx.exports.export_batch(
            self.submitter, [rec("a"), rec("b", institution="inst-b")],
            purpose="p", idempotency_key="export-1",
        )
        self.assertEqual(r1["batch_id"], r2["batch_id"])
        self.assertTrue(r2["replayed"])
        self.assertEqual(r2["denied"], 1)

    def test_duplicate_record_id_in_same_batch_rejected_upfront(self) -> None:
        with self.assertRaises(ValidationError):
            self.h.ctx.exports.export_batch(
                self.admin, [rec("dup"), rec("dup")]
            )
        # 没有产生任何批次
        conn = sqlite3.connect(self.h.db_path)
        try:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM export_batches").fetchone()[0],
                0,
            )
        finally:
            conn.close()

    def test_get_batch_access_control(self) -> None:
        result = self.h.ctx.exports.export_batch(self.admin, [rec("r1")])
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.exports.get_batch(self.admin_b, result["batch_id"])
        # 审计可查任意批次
        view = self.h.ctx.exports.get_batch(self.auditor, result["batch_id"])
        self.assertEqual(view["batch_id"], result["batch_id"])


class ControlledExportHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.server = HttpApiServer(
            self.h.ctx, host="127.0.0.1", port=0, bootstrap_token="boot"
        )
        self.server.start()
        host, port = self.server.address
        self.base = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.stop()
        self.h.close()

    def _req(self, method, path, body=None, token=None, bootstrap=None):
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token
        if bootstrap:
            headers["X-Bootstrap-Token"] = bootstrap
        req = urllib.request.Request(
            self.base + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _bootstrap(self, user_id, roles, institution_id, token):
        status, _ = self._req(
            "POST", "/v1/admin/users",
            {"user_id": user_id, "roles": roles,
             "institution_id": institution_id},
            bootstrap="boot",
        )
        self.assertEqual(status, 201)
        status, _ = self._req(
            "POST", "/v1/admin/tokens",
            {"user_id": user_id, "token": token}, bootstrap="boot",
        )
        self.assertEqual(status, 201)

    def test_export_over_http_denied_items_stay_in_manifest(self) -> None:
        self._bootstrap("sub-a", ["institution_submitter"], "inst-a", "tok-sub")
        body = {
            "purpose": "HTTP 批量导出",
            "records": [
                {"record_id": "n1", "institution_id": "inst-a",
                 "kind": "feedback", "sensitivity": "normal",
                 "fields": {"company": SECRET, "note": "普通反馈"}},
                {"record_id": "n2", "institution_id": "inst-b",
                 "kind": "feedback", "sensitivity": "normal",
                 "fields": {"company": "外机构机密"}},
                {"record_id": "n3", "institution_id": "inst-a",
                 "kind": "feedback", "sensitivity": "sensitive",
                 "fields": {"company": "敏感机密"}},
            ],
        }
        status, result = self._req("POST", "/v1/exports", body, token="tok-sub")
        self.assertEqual(status, 200, result)
        self.assertEqual(result["exported"], 1)
        self.assertEqual(result["denied"], 2)

        status, fetched = self._req(
            "GET", f"/v1/exports/{result['batch_id']}", token="tok-sub"
        )
        self.assertEqual(status, 200)
        denied = [i for i in fetched["items"] if i["status"] == "denied"]
        self.assertEqual(len(denied), 2)
        for item in denied:
            self.assertIsNone(item["fields"])
            self.assertIsNone(item["sha256"])
        serialized = json.dumps(fetched, ensure_ascii=False)
        self.assertNotIn("外机构机密", serialized)
        self.assertNotIn("敏感机密", serialized)
        self.assertIn(SECRET, serialized)  # 放行条目不受影响

        # 未认证请求被拒
        status, _ = self._req("GET", f"/v1/exports/{result['batch_id']}")
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
