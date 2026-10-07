//! Versioned evidence identity. Detection and occurrence lifecycle are independent.
use crate::security::{identity, Location, TaintPath};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CandidateAssessment {
    NeedsValidation,
    Confirmed,
    Rejected,
}

/// Hashes use Sentinel's SHA-256 of canonical JSON source strings.
/// These manifests describe assessed scope, not all repository content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceSnapshot {
    pub id: String,
    pub rule_sources: BTreeMap<String, String>,
    pub graph_sources: BTreeMap<String, String>,
}
impl EvidenceSnapshot {
    pub fn new(
        rule_sources: BTreeMap<String, String>,
        graph_sources: BTreeMap<String, String>,
    ) -> Self {
        Self {
            id: identity((&rule_sources, &graph_sources)),
            rule_sources,
            graph_sources,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectorProvenance {
    pub engine_version: String,
    pub rule_set_id: String,
    pub semantics_revision: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub schema_version: u32,
    pub finding_id: String,
    pub snapshot_id: String,
    pub location: Location,
    pub detector: DetectorProvenance,
    pub assessment: CandidateAssessment,
    pub confidence_basis: String,
    pub assumptions: Vec<String>,
    pub traces: Vec<TaintPath>,
}
