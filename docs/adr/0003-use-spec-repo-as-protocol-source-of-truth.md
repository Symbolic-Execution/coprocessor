# Use Spec Repo as Protocol Source of Truth

The Coprocessor implementation treats the sibling `../spec` repo as the
authoritative protocol source for behavior, terminology, API shapes, and
responsibility boundaries. Implementation changes that diverge from the spec
must either update the spec first or record an explicit ADR explaining the local
deviation.
