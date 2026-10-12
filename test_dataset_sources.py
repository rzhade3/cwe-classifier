"""Realistic offline fixtures for pinned vulnerability source adapters."""

import hashlib
import json
import shutil
import unittest
import uuid
from pathlib import Path

from dataset_sources import load_sources, snapshot_sha256


class SourceTests(unittest.TestCase):
    def setUp(self):
        # Keep all fixture operations within the repository, never system temp.
        self.root = Path(__file__).parent / (".source-tests-" + uuid.uuid4().hex)
        self.root.mkdir()
        self.addCleanup(shutil.rmtree, self.root)
        self.sources = []

    def write(self, name, value, jsonl=False):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        content = "\n".join(json.dumps(item) for item in value) if jsonl else json.dumps(value)
        path.write_text(content, encoding="utf-8")
        return path

    def source(self, kind, path, absolute=False):
        source = dict(kind=kind, path=str(path.resolve()) if absolute
                      else str(path.relative_to(self.root)),
                      sha256=snapshot_sha256(path), revision="2026-01-02")
        self.sources.append(source)
        return source

    def load(self):
        return load_sources(self.write("manifest.json", {"sources": self.sources}))

    def nvd(self, identifier="CVE-2025-1234", **extra):
        cve = dict(id=identifier, vulnStatus="Analyzed",
                   published="2025-03-14T12:30:00.000",
                   descriptions=[{"lang": "en", "value": "CWE-79 unsafe rendered input"},
                                 {"lang": "es", "value": "No importar"}],
                   weaknesses=[{"source": "nvd@nist.gov", "type": "Primary",
                                "description": [{"lang": "en", "value": "CWE-79"}]},
                               {"source": "vendor", "type": "Secondary",
                                "description": [{"lang": "en", "value": "CWE-89"}]}])
        cve.update(extra)
        return {"cve": cve}

    def cve(self, identifier="CVE-2025-1235", state="PUBLISHED"):
        return {
            "dataType": "CVE_RECORD", "dataVersion": "5.1",
            "cveMetadata": {"cveId": identifier, "state": state,
                            "datePublished": "2025-03-15T12:00:00.000Z"},
            "containers": {"cna": {
                "providerMetadata": {"orgId": "org", "shortName": "MITRE"},
                "affected": [{"vendor": "ExampleVendor", "product": "ExampleProduct",
                              "versions": [{"version": "1.0", "status": "affected"}]}],
                "descriptions": [{"lang": "en", "value": "Unescaped SQL parameters."}],
                "problemTypes": [{"descriptions": [
                    {"lang": "en", "type": "CWE", "cweId": "CWE-89",
                     "description": "CWE-89 SQL Injection"},
                    {"lang": "en", "description": "Related CWE-20 validation"}]}]}}}

    def ghsa(self, identifier="GHSA-abcd-1234-5678", **extra):
        value = dict(
            schema_version="1.4.0", id=identifier,
            aliases=["CVE-2025-1234"], published="2025-03-16T08:00:00Z",
            modified="2025-03-17T08:00:00Z",
            summary="Template injection", details="Untrusted CWE-79 markup is rendered.",
            affected=[{"package": {"ecosystem": "PyPI", "name": "example-package"},
                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
                      {"package": {"ecosystem": "npm", "name": "another-package"}}],
            database_specific={"github_reviewed": True, "cwe_ids": ["CWE-79", "CWE-94"]})
        value.update(extra)
        return value

    def normalized(self, identifier="VENDOR-1", **extra):
        value = dict(id=identifier, aliases=["CVE-2025-1234"], text="Unsafe CWE-079 input",
                     labels=["079", "CWE-89"], published="2025-03-17",
                     ecosystems=["npm"], vendors=["ExampleVendor"], ambiguous=False,
                     insufficient_information=False)
        value.update(extra)
        return value

    def test_nvd_feed_multiple_labels_and_exclusions(self):
        path = self.write("nvd.json", {"format": "NVD_CVE", "vulnerabilities": [
            self.nvd(), self.nvd("CVE-2025-2000", vulnStatus="Rejected"),
            self.nvd("CVE-2025-2001", descriptions=[]),
            self.nvd("CVE-2025-2002", weaknesses=[{"description": [
                {"lang": "en", "value": "NVD-CWE-noinfo"},
                {"lang": "en", "value": "NVD-CWE-Other"}]}])]})
        self.source("nvd", path, absolute=True)
        records, audit = self.load()
        self.assertEqual([record["labels"] for record in records], [["79", "89"], []])
        self.assertEqual(records[0]["published"], "2025-03-14")
        self.assertEqual(records[0]["text"], "CWE-79 unsafe rendered input")
        self.assertEqual(records[0]["aliases"], ["CVE-2025-1234"])
        self.assertFalse(records[0]["reviewed"])
        self.assertEqual(audit["counts"], dict(seen=4, accepted=2, excluded=2, metadata=0))
        self.assertEqual(audit["exclusions"], dict(rejected=1, missing_description=1))
        self.assertEqual(audit["manifest_sha256"],
                         hashlib.sha256((self.root / "manifest.json").read_bytes()).hexdigest())
        self.assertEqual(audit["sources"][0]["path"], str(path.resolve()))

    def test_cve_list_directory_and_single_file(self):
        published = self.cve()
        del published["cveMetadata"]["datePublished"]
        published["containers"]["cna"]["datePublished"] = "2025-03-18T10:00:00+01:00"
        self.write("cvelist/2025/1xxx/CVE-2025-1235.json", published)
        self.write("cvelist/2025/1xxx/rejected.json", self.cve("CVE-2025-2000", "REJECTED"))
        self.write("cvelist/2025/1xxx/reserved.json", self.cve("CVE-2025-2001", "RESERVED"))
        missing = self.cve("CVE-2025-2002")
        missing["containers"]["cna"]["descriptions"] = [{"lang": "fr", "value": "Français"}]
        self.write("cvelist/2025/1xxx/missing.json", missing)
        self.source("cve", self.root / "cvelist")
        self.source("cve", self.write("individual.json", self.cve("CVE-2025-3000")))
        records, audit = self.load()
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["labels"], ["89", "20"])
        self.assertEqual(records[0]["vendors"], ["ExampleVendor"])
        self.assertEqual(records[0]["published"], "2025-03-18")
        self.assertEqual(audit["exclusions"],
                         dict(missing_description=1, rejected=1, not_published=1))

    def test_cve_vendors_are_affected_vendors_not_reporting_cna(self):
        entry = self.cve()
        entry["containers"]["cna"]["affected"].extend([
            {"vendor": "AnotherVendor", "product": "OtherProduct"},
            {"vendor": "ExampleVendor", "product": "SecondProduct"},
            {"vendor": "N/A"}, {"vendor": "unknown"}, {"vendor": " n/a "},
            {"product": "UnspecifiedVendor"},
        ])
        self.source("cve", self.write("vendors.json", entry))
        records, _ = self.load()
        self.assertEqual(records[0]["vendors"], ["ExampleVendor", "AnotherVendor"])
        self.assertNotIn("MITRE", records[0]["vendors"])
        self.sources = []
        del entry["containers"]["cna"]["affected"]
        self.source("cve", self.write("no-vendors.json", entry))
        self.assertEqual(self.load()[0][0]["vendors"], [])

    def test_ghsa_official_directory_requires_review_and_not_withdrawn(self):
        self.write("advisories/github-reviewed/2025/03/GHSA-1.json", self.ghsa())
        self.write("advisories/github-reviewed/2025/03/GHSA-2.json",
                   self.ghsa("GHSA-withdrawn", withdrawn="2025-04-01T00:00:00Z"))
        self.write("advisories/unreviewed/2025/03/GHSA-3.json",
                   self.ghsa("GHSA-unreviewed", database_specific={"github_reviewed": False}))
        self.write("advisories/github-reviewed/GHSA-4.json",
                   self.ghsa("GHSA-no-text", summary="", details=""))
        self.source("ghsa", self.root / "advisories")
        records, audit = self.load()
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertTrue(record["reviewed"])
        self.assertEqual(record["aliases"], ["GHSA-abcd-1234-5678", "CVE-2025-1234"])
        self.assertEqual(record["text"],
                         "Template injection\n\nUntrusted CWE-79 markup is rendered.")
        self.assertEqual(record["ecosystems"], ["PyPI", "npm"])
        self.assertEqual(record["vendors"], [])
        self.assertEqual(record["labels"], ["79", "94"])
        self.assertEqual(audit["exclusions"],
                         dict(withdrawn=1, unreviewed=1, missing_description=1))

    def test_vendor_and_adjudication_jsonl(self):
        self.source("vendor", self.write("vendor.jsonl", [
            self.normalized(), self.normalized("VENDOR-2", labels=[],
                                               insufficient_information=True)], jsonl=True))
        self.source("adjudicated", self.write("adjudicated.jsonl", [
            self.normalized("EXPERT-1", expert_reviewed=True, adjudication_status="complete"),
            self.normalized("EXPERT-2", labels=[], expert_reviewed=True,
                            adjudication_status="pending"),
            self.normalized("EXPERT-3", expert_reviewed=False,
                            adjudication_status="complete"),
            self.normalized("EXPERT-4", expert_reviewed=True)], jsonl=True))
        records, _ = self.load()
        self.assertEqual(records[0]["labels"], ["79", "89"])
        self.assertFalse(records[0]["reviewed"])
        self.assertTrue(records[1]["insufficient_information"])
        self.assertEqual([record["reviewed"] for record in records[2:]],
                         [True, False, False, False])
        self.assertEqual(records[3]["labels"], [])
        self.assertEqual(records[3]["adjudication_status"], "pending")
        self.assertEqual(records[-1]["adjudication_status"], "pending")
        required = {"id", "aliases", "text", "labels", "published", "ecosystems", "vendors",
                    "source", "reviewed", "ambiguous", "insufficient_information",
                    "expert_reviewed", "kev"}
        self.assertEqual(set(records[0]), required)
        self.assertEqual(set(records[2]), required | {"adjudication_status"})

    def test_kev_metadata_join_does_not_supply_primary_text_or_gold(self):
        self.source("kev", self.write("kev.json", {
            "title": "CISA Known Exploited Vulnerabilities Catalog",
            "catalogVersion": "2025.03.20", "vulnerabilities": [{
                "cveID": "CVE-2025-1234", "vendorProject": "Example",
                "product": "Example", "dateAdded": "2025-03-20",
                "shortDescription": "KEV wording must not replace primary text",
                "cwes": ["CWE-999"]}, {"cveID": "CVE-2025-9999"}]}))
        self.source("ghsa", self.write("ghsa.json", self.ghsa()))
        self.source("nvd", self.write("nvd.json", {"vulnerabilities": [
            self.nvd(), self.nvd("CVE-2025-9998")]}))
        records, audit = self.load()
        self.assertEqual(len(records), 3)
        self.assertEqual([record["kev"] for record in records], [True, True, False])
        self.assertNotIn("999", records[0]["labels"])
        self.assertNotIn("KEV wording", records[0]["text"])
        self.assertEqual(audit["sources"][0]["counts"],
                         dict(seen=2, accepted=0, excluded=0, metadata=2))
        self.assertEqual(audit["counts"]["metadata"], 2)

    def test_directory_pin_is_documented_deterministic_and_detects_drift(self):
        root = self.root / "snapshot"
        a = self.write("snapshot/a.json", self.cve())
        b = self.write("snapshot/z/b.json", self.cve("CVE-2025-1236"))
        digest = hashlib.sha256()
        for path in (a, b):
            relative = path.relative_to(root).as_posix().encode()
            content = path.read_bytes()
            digest.update(len(relative).to_bytes(8, "big") + relative)
            digest.update(len(content).to_bytes(8, "big") + content)
        self.assertEqual(snapshot_sha256(root), digest.hexdigest())
        self.write("snapshot/.git/config.json", {"ignored": True})
        self.write("snapshot/.github/config.json", {"ignored": True})
        self.write("snapshot/node_modules/pkg/file.json", {"ignored": True})
        (root / "README.txt").write_text("ignored", encoding="utf-8")
        self.assertEqual(snapshot_sha256(root), digest.hexdigest())
        self.source("cve", root)
        self.assertEqual(len(self.load()[0]), 2)
        a.write_text(json.dumps(self.cve("CVE-2025-9999")), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.load()

    def test_file_pin_drift_and_symlinks(self):
        path = self.write("vendor.json", self.normalized())
        self.assertEqual(snapshot_sha256(path), hashlib.sha256(path.read_bytes()).hexdigest())
        self.source("vendor", path)
        path.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.load()
        link = self.root / "linked.json"
        link.symlink_to(path.resolve())
        with self.assertRaisesRegex(ValueError, "symlink"):
            snapshot_sha256(link)

    def test_iso_dates_and_strict_normalized_types(self):
        cases = [
            {"published": "2025-02-29"}, {"published": "2025-03-17garbage"},
            {"published": "2025-03-17T25:00:00Z"}, {"published": 20250317},
            {"labels": "79"}, {"labels": [79]}, {"labels": ["CWE-noinfo"]},
            {"aliases": "CVE-1"}, {"ecosystems": [None]}, {"vendors": {}},
            {"ambiguous": "false"}, {"expert_reviewed": 1},
            {"insufficient_information": "true"}, {"id": ""},
        ]
        for index, change in enumerate(cases):
            with self.subTest(change=change):
                self.sources = []
                self.source("vendor", self.write(f"bad-{index}.json", self.normalized(**change)))
                with self.assertRaises(ValueError):
                    self.load()
        self.sources = []
        self.source("vendor", self.write("good.json", self.normalized(published="")))
        self.assertEqual(self.load()[0][0]["published"], "")

    def test_missing_labels_and_bad_adjudication_status(self):
        missing = self.normalized()
        del missing["labels"]
        self.source("vendor", self.write("missing.json", missing))
        with self.assertRaisesRegex(ValueError, "requires labels"):
            self.load()
        self.sources = []
        self.source("adjudicated", self.write("bad-status.json",
                    self.normalized(adjudication_status="approved", expert_reviewed=True)))
        with self.assertRaisesRegex(ValueError, "adjudication_status"):
            self.load()

    def test_manifest_validation_and_jsonl_blank_lines(self):
        path = self.write("vendor.jsonl", [self.normalized()], jsonl=True)
        path.write_text("\n" + path.read_text() + "\n\n", encoding="utf-8")
        source = self.source("vendor", path)
        self.assertEqual(len(self.load()[0]), 1)
        for field, invalid in [("kind", "download"), ("sha256", "abc"),
                               ("revision", ""), ("path", None)]:
            with self.subTest(field=field):
                bad = dict(source, **{field: invalid})
                manifest = self.write("invalid.json", {"sources": [bad]})
                with self.assertRaises(ValueError):
                    load_sources(manifest)
        source["sha256"] = source["sha256"].upper()
        self.assertEqual(len(self.load()[0]), 1)

    def test_public_jsonl_and_invalid_public_types(self):
        self.source("nvd", self.write("nvd.jsonl", [self.nvd()], jsonl=True))
        self.assertEqual(self.load()[0][0]["source"], "nvd")
        self.sources = []
        self.source("ghsa", self.write("bad-ghsa.json", self.ghsa(
            database_specific={"github_reviewed": "true", "cwe_ids": []})))
        with self.assertRaisesRegex(ValueError, "boolean"):
            self.load()
        self.sources = []
        self.source("nvd", self.write("bad-nvd.json", self.nvd(descriptions="English")))
        with self.assertRaisesRegex(ValueError, "list"):
            self.load()


if __name__ == "__main__":
    unittest.main()
