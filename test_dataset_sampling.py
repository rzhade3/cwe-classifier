"""Standard-library tests for grouped, offline dataset sampling."""

import itertools
import unittest

from dataset_sampling import prepare_records


CATALOG = {79: {}, 89: {}, 22: {}}


def record(identifier, **kwargs):
    result = dict(
        id=identifier, aliases=[], text="Distinct issue " + identifier,
        labels=[79], published="2024-01-01", ecosystems=[], vendors=[],
        source="nvd", expert_reviewed=False, adjudication_status="pending",
        ambiguous=False, insufficient_information=False, kev=False)
    result.update(kwargs)
    return result


class SamplingTests(unittest.TestCase):
    def prepare(self, records, **kwargs):
        return prepare_records(records, CATALOG, **kwargs)

    def test_alias_chain_cross_source_canonical_and_permutation(self):
        records = [
            record("CVE-2024-123", aliases=["ghsa-abc"], source="nvd"),
            record("GHSA-ABC", aliases=["vendor-1"], source="ghsa"),
            record("vendor-1", source="vendor", text="Vendor canonical CWE-79 text",
                   published="2025-01-01", ecosystems=["Python"], kev=True)]
        expected = self.prepare(records)
        for order in itertools.permutations(records):
            self.assertEqual(expected, self.prepare(order))
        examples, audit, queue = expected
        self.assertEqual(len(examples), 1)
        self.assertEqual(examples[0]["id"], "CVE-2024-123")
        self.assertEqual(examples[0]["aliases"],
                         ["CVE-2024-123", "GHSA-ABC", "VENDOR-1"])
        self.assertEqual(examples[0]["text"], "Vendor canonical text")
        self.assertEqual(examples[0]["sources"], ["ghsa", "nvd", "vendor"])
        self.assertEqual(examples[0]["published"], "2025-01-01")
        self.assertIn("kev", examples[0]["slices"])
        self.assertEqual(queue, [])
        self.assertEqual(audit["groups_total"], 1)

    def test_near_duplicates_group_before_holdout_and_training(self):
        text = "buffer pointer arithmetic stack memory corruption remote execution parser"
        records = [
            record("old", text=text + " CWE-79"),
            record("new", text=text + " CWE-89 extra", published="2026-01-01")]
        examples, audit, _ = self.prepare(records, test_after="2025-01-01")
        self.assertEqual(len(examples), 1)
        self.assertEqual(examples[0]["split"], "test")
        self.assertEqual(examples[0]["aliases"], ["NEW", "OLD"])
        self.assertEqual(self.prepare(records, training_ids=["old"])[0], [])
        self.assertEqual(audit["groups_total"], 1)

    def test_exact_short_duplicates_and_short_near_texts(self):
        records = [record("a", text="Unsafe CWE-79 input"),
                   record("b", text="unsafe input"),
                   record("c", text="unsafe input extra")]
        examples, audit, _ = self.prepare(records)
        self.assertEqual(audit["groups_total"], 2)
        self.assertEqual(examples[0]["aliases"], ["A", "B"])

    def test_catalog_reference_anchor_and_alias_exclusion(self):
        catalog = {79: {"Observed Examples":
                       "::REFERENCE:cve-2024-123:DESCRIPTION:mentions "
                       "CVE-2024-999:LINK:https://host/CVE-2024-888::"}}
        records = [record("alias", aliases=["CVE-2024-123"], text="same"),
                   record("duplicate", text="SAME"),
                   record("CVE-2024-999"), record("CVE-2024-888")]
        examples, audit, _ = prepare_records(records, catalog, sample_size=1,
                                             balanced_per_label=0)
        self.assertEqual(audit["catalog_overlap"], 1)
        self.assertEqual(len(audit["excluded"][0]["aliases"]), 3)
        self.assertNotIn("ALIAS", {e["id"] for e in examples})
        self.assertEqual(audit["primary_eligible"], 2)

    def test_train_chain_exclusion_precedes_sampling(self):
        records = [record("a", aliases=["b"]),
                   record("b", aliases=["train"]), record("safe")]
        examples, audit, _ = self.prepare(records, training_ids=["TrAiN"],
                                          sample_size=0)
        self.assertEqual([e["id"] for e in examples], ["SAFE"])
        self.assertEqual(audit["training_overlap"], 1)

    def test_holdouts_and_latest_annotation_date(self):
        records = [
            record("old"),
            record("time", published="2025-01-01"),
            record("eco", ecosystems=["PyThOn"]),
            record("vendor", vendors=["ACME"]),
            record("src", source="ghsa", aliases=["mirror"]),
            record("mirror", source="nvd"),
            record("late", aliases=["early"], published="2026-01-01"),
            record("early", published="2020-01-01")]
        examples, _, _ = self.prepare(
            records, test_after="2025-01-01", holdout_ecosystems=["python"],
            holdout_vendors=["acme"], holdout_sources=["GHSA"], dev_fraction=0)
        splits = {e["id"]: e["split"] for e in examples}
        self.assertEqual(splits.pop("OLD"), "dev")
        self.assertEqual(set(splits.values()), {"test"})

    def test_missing_date_quarantines_even_dated_alias(self):
        records = [record("a", aliases=["b"], published=""),
                   record("b", published="2026-01-01")]
        examples, audit, _ = self.prepare(records, test_after="2025-01-01")
        self.assertEqual(examples[0]["split"], "quarantine")
        self.assertNotIn("natural", examples[0]["slices"])
        self.assertNotIn("balanced", examples[0]["slices"])
        self.assertEqual(audit["missing_date"], 1)
        self.assertIn("natural", self.prepare(records)[0][0]["slices"])

    def test_natural_uniform_and_balanced_independent_strict_caps(self):
        records = [record("issue-" + str(i), labels=[79, 89] if i % 3 == 0
                          else [79]) for i in range(30)]
        full, full_audit, _ = self.prepare(records, dev_fraction=.5,
                                          balanced_per_label=3)
        small, small_audit, _ = self.prepare(records, dev_fraction=.5,
                                            sample_size=1, balanced_per_label=3)
        for split in ("dev", "test"):
            self.assertEqual(small_audit["natural_counts"][split], 1)
            ids = lambda es: {e["id"] for e in es if e["split"] == split
                              and "balanced" in e["slices"]}
            self.assertEqual(ids(full), ids(small))
            for label in ("CWE-79", "CWE-89"):
                self.assertLessEqual(sum(
                    label in e["labels"] for e in small
                    if e["split"] == split and "balanced" in e["slices"]), 3)
        self.assertEqual(full_audit["assignments"], small_audit["assignments"])
        relabeled = [dict(r, labels=[22]) for r in records]
        other = self.prepare(relabeled, dev_fraction=.5, sample_size=1)[0]
        self.assertEqual({e["id"] for e in small if "natural" in e["slices"]},
                         {e["id"] for e in other if "natural" in e["slices"]})

    def test_conflicting_weak_views_not_unioned_and_expert_override(self):
        records = [record("a", labels=[79], ambiguous=True),
                   record("a", labels=[89], source="vendor")]
        examples, audit, queue = self.prepare(records)
        self.assertEqual(examples[0]["labels"], ["CWE-89"])
        self.assertTrue(examples[0]["annotation_conflict"])
        self.assertNotIn("natural", examples[0]["slices"])
        self.assertEqual(len(queue[0]["evidence"]), 2)
        expert = record("a", source="adjudicated", labels=[22, 79],
                        expert_reviewed=True, adjudication_status="complete",
                        text="Completed manual adjudication")
        examples, _, queue = self.prepare(records + [expert])
        self.assertEqual(examples[0]["labels"], ["CWE-22", "CWE-79"])
        self.assertFalse(examples[0]["annotation_conflict"])
        self.assertFalse(examples[0]["ambiguous"])
        self.assertIn("natural", examples[0]["slices"])
        self.assertEqual(queue, [])
        other = dict(expert, labels=[89])
        examples, _, queue = self.prepare(records + [expert, other])
        self.assertTrue(examples[0]["annotation_conflict"])
        self.assertNotIn("natural", examples[0]["slices"])
        self.assertEqual(len(queue), 1)

    def test_unsupported_gold_retained_and_no_gold_diagnostics(self):
        records = [record("mixed", labels=[79, 999]),
                   record("unsupported", labels=[999]),
                   record("empty", labels=[]),
                   record("insufficient", insufficient_information=True),
                   record("pending", expert_reviewed=True)]
        examples, audit, queue = self.prepare(records)
        by_id = {e["id"]: e for e in examples}
        self.assertEqual(by_id["MIXED"]["labels"], ["CWE-79", "CWE-999"])
        self.assertIn("natural", by_id["MIXED"]["slices"])
        self.assertNotIn("natural", by_id["UNSUPPORTED"]["slices"])
        self.assertEqual(by_id["EMPTY"]["labels"], [])
        self.assertFalse(by_id["PENDING"]["expert_reviewed"])
        self.assertNotIn("expert", by_id["PENDING"]["slices"])
        self.assertEqual(audit["unsupported_labels"], {"CWE-999": 2})
        self.assertEqual({r["id"] for r in queue},
                         {"EMPTY", "INSUFFICIENT", "PENDING"})

    def test_rare_uses_dev_only_and_unseen_test_gold(self):
        records = [record("dev-" + str(i), labels=[79]) for i in range(3)]
        records += [record("test-" + str(i), labels=[89], source="ghsa")
                    for i in range(12)]
        examples, audit, _ = self.prepare(
            records, holdout_sources=["ghsa"], rare_max_count=2, sample_size=1)
        self.assertEqual(audit["dev_label_counts"], {"CWE-79": 3})
        self.assertTrue(all(("rare" in e["slices"]) == (e["split"] == "test")
                            for e in examples))

    def test_diagnostic_slices_do_not_depend_on_primary_sampling(self):
        records = [
            record("kev", kev=True),
            record("expert", expert_reviewed=True, adjudication_status="complete"),
            record("rare", labels=[89]),
            record("ordinary")]
        examples, audit, queue = self.prepare(
            records, dev_fraction=1, sample_size=0, balanced_per_label=0,
            rare_max_count=1, near_duplicate_threshold=.95)
        by_id = {e["id"]: e for e in examples}
        self.assertEqual(set(by_id), {"KEV", "EXPERT", "RARE"})
        self.assertEqual(by_id["KEV"]["slices"], ["kev"])
        self.assertEqual(by_id["EXPERT"]["slices"], ["expert"])
        self.assertEqual(by_id["RARE"]["slices"], ["rare"])
        self.assertEqual(audit["natural_counts"]["dev"], 0)
        self.assertEqual(audit["balanced_counts"]["dev"], 0)
        self.assertEqual(audit["algorithm"]["near_duplicate_threshold"], .95)
        self.assertEqual(audit["slice_counts"]["dev"]["expert"], 1)
        self.assertEqual(queue, [])

    def test_expert_slice_requires_completed_consistent_sufficient_gold(self):
        records = [
            record("pending", expert_reviewed=True),
            record("conflict", expert_reviewed=True, adjudication_status="complete"),
            record("conflict", expert_reviewed=True, adjudication_status="complete",
                   source="vendor", labels=[89]),
            record("insufficient", expert_reviewed=True,
                   adjudication_status="complete", insufficient_information=True),
            record("no-gold", expert_reviewed=True, kev=True,
                   adjudication_status="complete", labels=[]),
            record("complete", expert_reviewed=True, adjudication_status="complete")]
        examples, _, queue = self.prepare(records, sample_size=0,
                                          balanced_per_label=0)
        experts = {e["id"] for e in examples if e["expert_reviewed"]}
        self.assertEqual(experts, {"COMPLETE"})
        self.assertEqual({e["id"] for e in examples if "expert" in e["slices"]},
                         experts)
        self.assertEqual({r["id"] for r in queue},
                         {"PENDING", "CONFLICT", "INSUFFICIENT", "NO-GOLD"})
        self.assertTrue(all("rare" not in e["slices"] and "kev" not in e["slices"]
                            for e in examples
                            if e["ambiguous"] or e["insufficient_information"]
                            or not e["labels"]))

    def test_ambiguous_completed_expert_is_not_a_valid_override(self):
        weak = record("ambiguous", source="vendor", labels=[79])
        expert = record(
            "ambiguous", source="adjudicated", labels=[89], expert_reviewed=True,
            adjudication_status="complete", ambiguous=True)
        examples, _, queue = self.prepare([weak, expert])
        example = examples[0]
        self.assertEqual(example["labels"], ["CWE-89"])
        self.assertTrue(example["ambiguous"])
        self.assertFalse(example["expert_reviewed"])
        self.assertEqual(example["split"], "quarantine")
        self.assertFalse({"natural", "balanced", "expert"} & set(example["slices"]))
        self.assertEqual(len(queue), 1)
        for invalid in (dict(expert, ambiguous=False, insufficient_information=True),
                        dict(expert, ambiguous=False, labels=[])):
            with self.subTest(invalid=invalid):
                examples, _, queue = self.prepare([weak, invalid])
                self.assertEqual(examples[0]["split"], "quarantine")
                self.assertEqual(examples[0]["labels"],
                                 [] if not invalid["labels"] else ["CWE-89"])
                self.assertFalse(examples[0]["expert_reviewed"])
                self.assertNotIn("natural", examples[0]["slices"])
                self.assertEqual(len(queue), 1)
        examples, _, queue = self.prepare([
            weak, dict(expert, ambiguous=False),
            dict(expert, ambiguous=False, labels=[22])])
        self.assertTrue(examples[0]["annotation_conflict"])
        self.assertEqual(examples[0]["split"], "quarantine")
        self.assertEqual(len(queue), 1)

    def test_empty_sanitized_canonical_text_is_quarantined(self):
        records = [record("empty", text=" CWE-79 CWE 089 "),
                   record("empty", source="cve", text="Longer source description"),
                   record("empty", source="adjudicated", text="CWE-79",
                          expert_reviewed=True, adjudication_status="complete")]
        examples, audit, queue = self.prepare(records)
        example = examples[0]
        self.assertEqual(example["text"], "")
        self.assertEqual(example["split"], "quarantine")
        self.assertTrue(example["insufficient_information"])
        self.assertFalse(example["expert_reviewed"])
        self.assertNotIn("natural", example["slices"])
        self.assertNotIn("balanced", example["slices"])
        self.assertNotIn("expert", example["slices"])
        self.assertEqual(audit["empty_text"], 1)
        self.assertEqual(audit["primary_eligible"], 0)
        self.assertEqual(len(queue), 1)
        self.assertIn("empty_text", queue[0]["reasons"])

    def test_pending_adjudication_is_evidence_not_gold_or_preferred_text(self):
        pending = record(
            "pending", source="adjudicated", expert_reviewed=True,
            labels=[89], text="Suggested annotation awaiting adjudication")
        examples, audit, queue = self.prepare([pending])
        self.assertEqual(examples[0]["labels"], [])
        self.assertNotIn("natural", examples[0]["slices"])
        self.assertNotIn("balanced", examples[0]["slices"])
        self.assertFalse(examples[0]["expert_reviewed"])
        self.assertEqual(audit["no_gold"], 1)
        self.assertEqual(queue[0]["source_labels"][0]["labels"], ["CWE-89"])
        self.assertEqual(queue[0]["evidence"][0]["text"], pending["text"])
        vendor = record("pending", source="vendor", labels=[79],
                        text="Vendor documented original description")
        examples, audit, queue = self.prepare([pending, vendor])
        self.assertEqual(examples[0]["labels"], ["CWE-79"])
        self.assertEqual(examples[0]["text"], vendor["text"])
        self.assertFalse(examples[0]["annotation_conflict"])
        self.assertIn("natural", examples[0]["slices"])
        self.assertEqual(len(queue[0]["source_labels"]), 2)
        self.assertNotIn("labels", queue[0])
        _, _, queue = self.prepare([dict(pending, expert_reviewed=False), vendor])
        self.assertEqual(len(queue), 1)

    def test_default_budgets_bound_large_all_rare_population(self):
        records = [record("issue-" + str(i)) for i in range(1200)]
        examples, audit, _ = self.prepare(records, dev_fraction=0)
        self.assertEqual(len(examples), 300)
        self.assertEqual(audit["natural_counts"]["test"], 200)
        self.assertEqual(audit["slice_counts"]["test"]["rare"], 300)
        self.assertEqual(audit["population_counts"]["test"]["eligible"], 1200)
        self.assertEqual(audit["budget_selection"]["test"]
                         ["excluded_eligible_due_budget"], 900)
        self.assertEqual(audit["budgets"]["max_examples_per_split"], 300)
        other, other_audit, _ = self.prepare(
            records, dev_fraction=0, sample_size=20, max_examples_per_split=30)
        self.assertEqual(len(other), 30)
        self.assertEqual(audit["assignments"], other_audit["assignments"])
        natural = lambda rows: {e["id"] for e in rows if "natural" in e["slices"]}
        self.assertLessEqual(natural(other), natural(examples))

    def test_budget_coverage_determinism_and_natural_first(self):
        records = [
            record("common-" + str(i), labels=[79]) for i in range(100)]
        records += [
            record("kev", labels=[89], source="vendor", kev=True),
            record("expert", labels=[22], source="adjudicated",
                   expert_reviewed=True, adjudication_status="complete"),
            record("ghsa", labels=[89], source="ghsa")]
        kwargs = dict(dev_fraction=0, sample_size=3, max_examples_per_split=8)
        expected = self.prepare(records, **kwargs)
        self.assertEqual(expected, self.prepare(records[::-1], **kwargs))
        examples, audit, _ = expected
        self.assertLessEqual(len(examples), 8)
        self.assertEqual(audit["natural_counts"]["test"], 3)
        self.assertEqual(audit["coverage"]["test"]["label"]["uncovered"], [])
        self.assertEqual(audit["coverage"]["test"]["source"]["uncovered"], [])
        self.assertIn("KEV", {e["id"] for e in examples})
        self.assertIn("EXPERT", {e["id"] for e in examples})
        no_diagnostics = self.prepare(
            records, dev_fraction=0, sample_size=3, max_examples_per_split=3)[0]
        self.assertEqual({e["id"] for e in examples if "natural" in e["slices"]},
                         {e["id"] for e in no_diagnostics})

    def test_none_and_zero_budgets_and_review_retention(self):
        records = [record("issue-" + str(i)) for i in range(20)]
        examples, audit, _ = self.prepare(
            records, dev_fraction=0, sample_size=None, max_examples_per_split=7)
        self.assertEqual(len(examples), 7)
        self.assertEqual(audit["natural_counts"]["test"], 7)
        unresolved = record("review", labels=[], ambiguous=True)
        examples, audit, queue = self.prepare(
            records + [unresolved], sample_size=0, max_examples_per_split=0)
        self.assertEqual(examples, [])
        self.assertEqual(len(queue), 1)
        self.assertEqual(len(audit["diagnostics"]), 1)
        with self.assertRaises(ValueError):
            self.prepare(records, sample_size=8, max_examples_per_split=7)

    def test_validation_and_input_not_modified(self):
        records = [record("a", aliases=["Mixed"], labels=[79, "CWE-079"])]
        import copy
        original = copy.deepcopy(records)
        self.prepare(records)
        self.assertEqual(records, original)
        for kwargs in (dict(sample_size=-1), dict(dev_fraction=float("nan")),
                       dict(near_duplicate_threshold=2), dict(seed=True),
                       dict(max_examples_per_split=-1),
                       dict(test_after="2025-02-30")):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.prepare(records, **kwargs)


if __name__ == "__main__":
    unittest.main()
