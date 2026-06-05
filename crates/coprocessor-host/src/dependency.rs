/// Named dependencies that the Coprocessor Host monitors for availability.

const ALL_DEPENDENCIES: [DependencyName; 3] = [
    DependencyName::SymVmEventSurface,
    DependencyName::Mpc,
    DependencyName::Enclave,
];

/// Named dependencies that the Coprocessor Host requires before it can serve
/// resolution work. Each variant marks a seam that future slices will wire.
/// Until a seam is wired, the host reports it as `Unavailable` in
/// [`super::lifecycle::Readiness`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DependencyName {
    /// Chain Event Ingestion from the `symVM` Event Surface.
    SymVmEventSurface,
    /// MPC threshold-key custody and ciphertext transformation.
    Mpc,
    /// Private computation Enclave runtime.
    Enclave,
}

impl DependencyName {
    /// Every dependency the host runtime currently models. The set is closed:
    /// adding a dependency means extending [`DependencyName`] and surfacing the
    /// seam in the readiness contract.
    pub fn all() -> [DependencyName; 3] {
        ALL_DEPENDENCIES
    }
}
