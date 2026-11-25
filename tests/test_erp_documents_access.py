"""ERP 자료실 열람 권한 규칙 시험 (erp/documents.py, DB 없이 실행)."""
import importlib.util
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "erp_documents", Path(__file__).resolve().parents[1] / "erp" / "documents.py"
)
documents = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(documents)


def user(department, role):
    return {"department": department, "role": role}


def doc(department, level):
    return {"department": department, "level": level}


class DocumentAccessTests(unittest.TestCase):
    def test_public_is_open_to_everyone(self):
        for dept in ("영업", "인사", "보안"):
            for role in ("member", "manager"):
                self.assertTrue(documents.can_read(user(dept, role), doc(None, "public"))[0])

    def test_dept_document_needs_same_department(self):
        self.assertTrue(documents.can_read(user("인사", "member"), doc("인사", "dept"))[0])
        self.assertFalse(documents.can_read(user("영업", "member"), doc("인사", "dept"))[0])

    def test_secret_needs_same_department_manager(self):
        self.assertTrue(documents.can_read(user("인사", "manager"), doc("인사", "secret"))[0])
        self.assertFalse(documents.can_read(user("인사", "member"), doc("인사", "secret"))[0])

    def test_manager_of_other_department_is_denied(self):
        self.assertFalse(documents.can_read(user("영업", "manager"), doc("인사", "secret"))[0])
        self.assertFalse(documents.can_read(user("영업", "manager"), doc("인사", "dept"))[0])

    def test_security_team_gets_no_special_access(self):
        self.assertFalse(documents.can_read(user("보안", "manager"), doc("인사", "secret"))[0])
        self.assertFalse(documents.can_read(user("보안", "member"), doc("인사", "dept"))[0])

    def test_unknown_level_is_denied(self):
        self.assertFalse(documents.can_read(user("인사", "manager"), doc("인사", "weird"))[0])

    def test_seed_documents_are_valid(self):
        ids = set()
        for title, dept, level, body in documents.SEED_DOCUMENTS:
            self.assertIn(level, documents.LEVELS)
            self.assertTrue(body.strip())
            self.assertEqual(dept is None, level == "public")
            ids.add(documents.doc_id(title))
        self.assertEqual(len(ids), len(documents.SEED_DOCUMENTS))
        self.assertEqual(documents.doc_id("포털 이용 안내"), documents.doc_id("포털 이용 안내"))

    def test_special_document_grant_allows_individual_cross_department_read(self):
        hr_doc_id = documents.doc_id("인사 업무 절차 안내")
        hr_doc = {"public_id": hr_doc_id, "department": "인사", "level": "dept"}
        other_hr_doc = {"public_id": documents.doc_id("급여 지급 규정"), "department": "인사", "level": "secret"}
        alice = user("영업", "member")
        self.assertFalse(documents.can_read(alice, hr_doc)[0])
        self.assertTrue(documents.can_read(alice, hr_doc, {hr_doc_id})[0])
        self.assertFalse(documents.can_read(alice, other_hr_doc, {hr_doc_id})[0])

    def test_revoked_retired_account_cannot_read_any_document(self):
        hr_doc_id = documents.doc_id("인사 업무 절차 안내")
        retired_alice = {"department": "영업", "role": "member", "is_revoked": True}
        self.assertFalse(documents.can_read(retired_alice, doc(None, "public"))[0])
        self.assertFalse(documents.can_read(retired_alice, doc("영업", "dept"))[0])
        self.assertFalse(
            documents.can_read(
                retired_alice,
                {"public_id": hr_doc_id, "department": "인사", "level": "dept"},
                {hr_doc_id},
            )[0]
        )


if __name__ == "__main__":
    unittest.main()
