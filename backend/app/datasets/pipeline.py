"""Validation pipeline and split manager for MailSentra datasets."""

import os
import re
import json
import hashlib
from typing import Dict, List, Tuple, Any, Optional, Set, Union
from app.datasets.contracts import CanonicalThreatLabel


class DatasetValidationPipeline:
    """Manages parsing, deduplication, leak-free group-aware splitting, and evaluation."""

    def __init__(self):
        self.seen_hashes = set()
        self.duplicates_found = 0

    def ingest_records(self, adapter, raw_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        processed = []
        for raw in raw_records:
            norm = adapter.normalize_record(raw)
            content_hash = norm.get("content_sha256") or norm.get("file_sha256")
            if content_hash in self.seen_hashes:
                self.duplicates_found += 1
                norm["is_duplicate"] = True
            else:
                self.seen_hashes.add(content_hash)
                norm["is_duplicate"] = False
            processed.append(norm)
        return processed

    def get_cluster_key(self, rec: Dict[str, Any]) -> str:
        """Determines the group-aware clustering key to prevent leakage between splits.
        
        Guarantees that messages from the same phishing campaign or matching subject
        fingerprints are isolated to a single partition.
        """
        # 1. Campaign Cluster ID
        if rec.get("campaign_cluster_id"):
            return f"campaign:{rec['campaign_cluster_id']}"

        # 2. Normalized Subject Fingerprint for campaign near-duplicates
        subj = rec.get("subject", "")
        if subj:
            norm_subj = re.sub(r"(?i)^(re|fwd|fw):\s*", "", subj).strip().lower()
            norm_subj = re.sub(r"\d+", "#", norm_subj)
            if len(norm_subj) > 8:
                return f"subject_fp:{norm_subj[:64]}"

        # 3. Content hash
        content_hash = rec.get("content_sha256") or rec.get("file_sha256")
        if content_hash:
            return f"content:{content_hash}"

        # 4. Fallback identifier
        rec_id = rec.get("record_id") or rec.get("message_id") or rec.get("url") or rec.get("filename") or "unknown"
        return f"id:{rec_id}"

    def split_records(
        self,
        records: List[Dict[str, Any]],
        train_ratio: float = 0.7,
        test_ratio: float = 0.3,
        return_telemetry: bool = False,
        prohibit_epvme_lexical: bool = True,
        benchmark_target: Optional[str] = None,
    ) -> Any:
        """Group-aware, deterministic partition split guaranteeing zero cross-split campaign leakage.
        
        Clusters records by campaign/subject template and assigns the entire cluster
        deterministically to either train or test using SHA-256 modular hashing.
        """
        # Integrity check: Prohibit EPVME from independent lexical phishing benchmarks
        if prohibit_epvme_lexical:
            is_lexical_target = benchmark_target in ("lexical_phishing", "phishing_lexical")
            for r in records:
                is_r_lexical = r.get("benchmark_type") in ("lexical_phishing", "phishing_lexical")
                if r.get("dataset_id") == "DS-SS-01" and (is_lexical_target or is_r_lexical):
                    raise ValueError(
                        "EPVME (DS-SS-01) is a TRANSFORMED_DERIVATIVE corpus with known third-party body overlap. "
                        "It is strictly prohibited from use as an independent lexical phishing benchmark."
                    )

        # 1. Group records by cluster key (excluding exact duplicates)
        clusters: Dict[str, List[Dict[str, Any]]] = {}
        duplicates_count = 0
        unsupported_count = 0

        for rec in records:
            if rec.get("is_duplicate"):
                duplicates_count += 1
                continue
            if rec.get("is_unsupported"):
                unsupported_count += 1
                continue

            ckey = self.get_cluster_key(rec)
            rec["cluster_key"] = ckey
            clusters.setdefault(ckey, []).append(rec)

        # 2. Deterministic cluster-level partition
        train_set: List[Dict[str, Any]] = []
        test_set: List[Dict[str, Any]] = []
        train_clusters: Set[str] = set()
        test_clusters: Set[str] = set()

        for ckey, cluster_recs in sorted(clusters.items(), key=lambda x: x[0]):
            # Deterministic SHA-256 hash modulo 100
            hash_val = int(hashlib.sha256(ckey.encode("utf-8")).hexdigest(), 16) % 100
            if hash_val < int(train_ratio * 100):
                train_clusters.add(ckey)
                for r in cluster_recs:
                    r["split"] = "train"
                    train_set.append(r)
            else:
                test_clusters.add(ckey)
                for r in cluster_recs:
                    r["split"] = "test"
                    test_set.append(r)

        telemetry = {
            "total_records_input": len(records),
            "duplicates_excluded": duplicates_count,
            "unsupported_records": unsupported_count,
            "total_clusters": len(clusters),
            "train_clusters": len(train_clusters),
            "test_clusters": len(test_clusters),
            "train_records": len(train_set),
            "test_records": len(test_set),
            "cross_split_leakage_detected": not train_clusters.isdisjoint(test_clusters),
        }

        if return_telemetry:
            return train_set, test_set, telemetry
        return train_set, test_set
