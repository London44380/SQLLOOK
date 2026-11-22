#!/usr/bin/env python3
"""Unit tests for sqllook's pure validation/parsing logic.

No database connection involved - everything here runs on synthetic,
throwaway fixtures (never on a real imported dump), so these are safe to
run anytime, including before publishing the tool.
"""
import tempfile
import unittest
from pathlib import Path

import sqllook as d


class ValidateSelectQuery(unittest.TestCase):
    def ok(self, q):
        self.assertEqual(d.validate_select_query(q), q.rstrip(";").strip())

    def rejected(self, q):
        with self.assertRaises(d.SqlError):
            d.validate_select_query(q)

    def test_allows_read_only_statements(self):
        for q in [
            "SELECT 1",
            "SELECT 1;",
            "select * from t",
            "SHOW TABLES",
            "DESCRIBE t",
            "DESC t",
            "EXPLAIN SELECT 1",
            "  SELECT 1  ",
        ]:
            self.ok(q)

    def test_rejects_empty(self):
        self.rejected("")
        self.rejected("   ")

    def test_rejects_non_select_statements(self):
        for q in [
            "INSERT INTO x VALUES (1)",
            "UPDATE x SET a=1",
            "DELETE FROM x",
            "DROP TABLE x",
            "ALTER TABLE x ADD COLUMN y INT",
            "CREATE TABLE x (a INT)",
            "GRANT ALL ON x.* TO 'y'@'localhost'",
        ]:
            self.rejected(q)

    def test_rejects_stacked_statements(self):
        self.rejected("SELECT 1; DROP TABLE x")
        self.rejected("SELECT 1;; ")
        self.rejected("SHOW TABLES; SELECT 1")

    def test_rejects_forbidden_keyword_even_inside_a_select(self):
        self.rejected("SELECT LOAD_FILE('/etc/passwd')")
        self.rejected("SELECT 1 INTO OUTFILE '/tmp/x'")
        self.rejected("SELECT * FROM x WHERE 1=1; SET GLOBAL x=1")

    def test_rejects_system_schema_access(self):
        self.rejected("SELECT * FROM mysql.user")
        self.rejected("SELECT * FROM INFORMATION_SCHEMA.tables")
        self.rejected("select * from Performance_Schema.threads")
        self.rejected("SELECT * FROM sys.x")

    def test_known_false_positive_is_acceptable(self):
        # A literal string that merely contains "mysql." is blocked too.
        # Over-blocking here is a safe failure mode (read-only grants are
        # the real guarantee anyway), not a security bug - documented so
        # nobody "fixes" the regex into something more permissive.
        self.rejected("SELECT * FROM t WHERE note = 'see mysql.user docs'")


class ValidateIdent(unittest.TestCase):
    def test_accepts_known_valid_identifier(self):
        self.assertEqual(d.validate_ident("my_table1", {"my_table1"}, "table"), "my_table1")

    def test_rejects_unknown_identifier(self):
        with self.assertRaises(d.SqlError):
            d.validate_ident("not_in_list", {"other"}, "table")

    def test_rejects_injection_attempts_even_if_allowlisted(self):
        # Defense in depth: even if something slipped into the "known" set,
        # the character-level check still blocks it.
        known = {"a`; DROP TABLE x; --", "bad-name", "bad;name", ""}
        for bad in known:
            with self.assertRaises(d.SqlError):
                d.validate_ident(bad, known, "table")


class DetectDbName(unittest.TestCase):
    def _write(self, text):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".sql", delete=False)
        f.write(text)
        f.close()
        return Path(f.name)

    def test_detects_backticked_database_name(self):
        p = self._write(
            "-- MariaDB dump\n"
            "CREATE DATABASE /*!32312 IF NOT EXISTS*/ `testdb` DEFAULT CHARACTER SET utf8mb4;\n"
            "USE `testdb`;\n"
        )
        try:
            self.assertEqual(d.detect_db_name(p), "testdb")
        finally:
            p.unlink()

    def test_returns_none_when_absent(self):
        p = self._write("CREATE TABLE t (a INT);\n")
        try:
            self.assertIsNone(d.detect_db_name(p))
        finally:
            p.unlink()


class ExtractDatabaseSection(unittest.TestCase):
    def setUp(self):
        self.tmp_home = Path(tempfile.mkdtemp())
        self._orig_home = d.HOME
        d.HOME = self.tmp_home

    def tearDown(self):
        d.HOME = self._orig_home

    def _write(self, text):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".sql", delete=False)
        f.write(text)
        f.close()
        return Path(f.name)

    def test_isolates_only_the_requested_database(self):
        dump = self._write(
            "SET NAMES utf8mb4;\n"
            "-- Current Database: `mysql`\n"
            "CREATE USER 'root'@'%' IDENTIFIED BY 'leaked';\n"
            "-- Current Database: `appdb`\n"
            "CREATE TABLE t (a INT);\n"
            "INSERT INTO t VALUES (1);\n"
            "-- Current Database: `other`\n"
            "CREATE TABLE unrelated (b INT);\n"
        )
        try:
            section = d.extract_database_section(dump, "appdb")
            try:
                content = section.read_text()
                self.assertIn("CREATE TABLE t (a INT);", content)
                self.assertNotIn("CREATE USER", content)
                self.assertNotIn("unrelated", content)
                self.assertIn("SET FOREIGN_KEY_CHECKS=0;", content)
                self.assertIn("SET FOREIGN_KEY_CHECKS=1;", content)
            finally:
                section.unlink(missing_ok=True)
        finally:
            dump.unlink()

    def test_returns_none_for_plain_single_database_dump(self):
        dump = self._write("CREATE TABLE t (a INT);\nINSERT INTO t VALUES (1);\n")
        try:
            self.assertIsNone(d.extract_database_section(dump, "appdb"))
        finally:
            dump.unlink()


if __name__ == "__main__":
    unittest.main()
