use serde::{Deserialize, Serialize};

/// Stable wire identifier for a metric recorded by `keyhog-profile`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(usize)]
pub enum MetricId {
    SourceAcquire = 0,
    SourceWalk,
    SourceRead,
    Preprocess,
    Phase1Triggers,
    BackendDispatch,
    HotPatterns,
    ConfirmedPatterns,
    Phase2Prefilter,
    Phase2KeywordAc,
    Phase2SharedAc,
    Phase2AnchoredVerify,
    Phase2WholeChunk,
    GenericDetection,
    Entropy,
    MachineLearning,
    Decode,
    Suppression,
    LiveVerification,
    Reporting,
    SourceQueueWait,
    IncrementalLookup,
    BackendSelect,
    ResultMerge,
    ScannerQueueWait,
    InputBytes,
    InputUnits,
    WallTime,
    ProcessCpuTime,
    ResidentMemory,
    VirtualMemory,
    ProcessThreads,
    Phase2PrefilterMarkCalls,
    Phase2PrefilterGateSkips,
    Phase2PrefilterPerPatternWork,
    Phase2PrefilterHsServed,
    Phase2PrefilterRegexsetServed,
    DecodeParentChunks,
    DecodeDerivedChunks,
    DecodeExtractCalls,
    DecodeExtractBytes,
    GenericPrefilterCalls,
    GenericKeywordLines,
    GenericRegexCaptures,
    GenericEmits,
    MlBatchCalls,
    MlBatchCandidates,
    MlBatchCallsGe64,
    MlBatchCandidatesGe64,
    DecodeExtractNs,
    GenericPrefilterNs,
    GenericExtractNs,
    Phase2PrefilterHsScanNs,
    Phase2PrefilterDroppedHostNs,
    MlFeatureNs,
    MlScoreNs,
    MlBatchSize,
    DecodeDerivedBytes,
    HardwareCycles,
    HardwareInstructions,
    HardwareCacheReferences,
    HardwareCacheMisses,
    HardwareBranchInstructions,
    HardwareBranchMisses,
    HardwareStalledCyclesFrontend,
    HardwareStalledCyclesBackend,
    SchedulerVoluntaryContextSwitches,
    SchedulerInvoluntaryContextSwitches,
    SchedulerCpuMigrations,
    SchedulerDelayNs,
    GpuDispatchCalls,
    GpuUploadBytes,
    GpuReadbackBytes,
    GpuUploadNs,
    GpuReadbackNs,
    GpuSubmitToCompleteNs,
    GpuKernelNs,
    GpuQueueWaitNs,
    GpuAllocCalls,
    GpuAllocBytes,
    GpuFreeBytes,
    GpuCompileCalls,
    GpuCompileNs,
    GpuPipelineCacheHits,
    GpuPipelineCacheMisses,
    GpuFaults,
    GpuRetries,
    GpuRecoveries,
    GpuResidualBatches,
    GpuOverlapNs,
    GpuResidentBytes,
    GpuPeakResidentBytes,
    AllocationCount,
    DeallocationCount,
    AllocationBytes,
    DeallocationBytes,
    AllocationLiveBytes,
    AllocationPeakLiveBytes,
    MinorFaults,
    MajorFaults,
    IoReadBytes,
    IoWriteBytes,
    IoReadSyscalls,
    IoWriteSyscalls,
    IoCancelledWriteBytes,
    ResidentHighWaterBytes,
    RetainedBufferBytes,
    RetainedBufferPeakBytes,
    NetworkBytesRead,
    NetworkBytesWritten,
    NetworkRequests,
    NetworkRetries,
    PageCacheColdObservations,
    PageCacheWarmObservations,
    PageCacheDirectObservations,
    FsOpenLatencyNs,
    FsReadLatencyNs,
    FsMetadataLatencyNs,
    NetworkLatencyNs,
    AutorouteCalibration,
    BoundaryScan,
    DetectorLoad,
    DetectorValidate,
    ExecutionPackSelect,
    ExecutionPackMap,
    BackendAcquire,
    BackendInit,
    Teardown,
    ScanPipeline,
    ScannerCompile,
    FilesScanned,
    BytesScanned,
    SkippedFiles,
    MatchesFound,
    StructuredParseFailures,
    StructuredOversizeSkips,
    DecodeTruncations,
    DecodeOversizeSkips,
    InvalidPatternIndexSkips,
    BoundaryResultCardinalityMismatches,
    BoundarySeamTruncations,
    LineOffsetMappingMismatches,
    ChunkDeadlineAborts,
    BinaryStringsNamedExclusions,
    SkippedOverMaxSize,
    SkippedBinary,
    SkippedExcluded,
    SkippedUnreadable,
    GitObjectUnreadable,
    SkippedArchiveTruncated,
    BinarySectionNameUnresolved,
    SourceTruncated,
    StructuredSourceParseFailures,
    ArchiveDuplicateScanUnavailable,
    GitLfsPointer,
    VendoredPathSuppressions,
    ExampleSuppressions,
    BinaryGhidraDegradedToStrings,
    BinaryUnreadable,
    GitBufferedBlobChunks,
    GpuMatcherNs,
    GpuCoalesceNs,
    GpuDispatchNs,
    GpuDeriveNs,
    GpuRecallFloorNs,
    Phase2GpuAdmissionNs,
    GpuCoalescedBytes,
    GpuMaxDispatchBytes,
    GpuPresenceBits,
    GpuUnderfireRecovered,
    GpuTriggerBits,
    Phase2GpuAdmitted,
    Phase2GpuEvidenceBits,
    Phase2GpuHaystackUploads,
    Phase2GpuCompleteChunks,
    Phase2GpuCompleteRows,
    Phase2GpuExcludedOversized,
    Phase2GpuExcludedNonAscii,
    Phase2AlwaysAnchorChunks,
    Phase2AlwaysAnchorCandidateRows,
    Phase2AlwaysAnchorCandidateCount,
    ConfirmedAnchorCandidateRows,
    ConfirmedAnchorCandidateCount,
    GenericKeywordCandidateRows,
    GenericKeywordCandidateCount,
    ConfirmedSuffixGateNs,
    ConfirmedSuffixGateCalls,
    ConfirmedSuffixGateSkips,
    ConfirmedCompanionGateNs,
    ConfirmedCompanionGateCalls,
    ConfirmedCompanionGateDenials,
    ConfirmedAnchorCollectNs,
    ConfirmedAnchorCollectCalls,
    ConfirmedExtractNs,
    ConfirmedExtractCalls,
    ConfirmedAnchoredMatches,
    ConfirmedWholeChunkMatches,
    ConfirmedHotDirectFilterSkips,
    PostprocessFragmentsNs,
    PostprocessFragmentsCalls,
    PostprocessFragmentsCandidates,
    PostprocessFragmentsMatches,
    PostprocessDedupNs,
    PostprocessDedupCalls,
    Phase2AnchorCollectNs,
    Phase2AnchorCollectCalls,
    Phase2AnchoredVerifyCandidates,
    Phase2AnchoredVerifyMatches,
    Phase2WholeChunkPatterns,
    Phase2WholeChunkMatches,
}

/// Stable identifier for a top-level production pipeline stage.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum MacroStageId {
    Acquire = 0,
    Scan,
    Resolve,
    Verify,
    Report,
}

impl MacroStageId {
    /// Every macro-stage identifier in stable wire order.
    pub const ALL: [Self; 5] = [
        Self::Acquire,
        Self::Scan,
        Self::Resolve,
        Self::Verify,
        Self::Report,
    ];

    /// Stable text label used by profiles and operator reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Acquire => "acquire",
            Self::Scan => "scan",
            Self::Resolve => "resolve",
            Self::Verify => "verify",
            Self::Report => "report",
        }
    }
}

/// Type-safe identifier for an additive monotonic metric.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum CounterId {
    InputBytes = 0,
    InputUnits,
    ProcessCpuTime,
    Phase2PrefilterMarkCalls,
    Phase2PrefilterGateSkips,
    Phase2PrefilterPerPatternWork,
    Phase2PrefilterHsServed,
    Phase2PrefilterRegexsetServed,
    DecodeParentChunks,
    DecodeDerivedChunks,
    DecodeExtractCalls,
    DecodeExtractBytes,
    GenericPrefilterCalls,
    GenericKeywordLines,
    GenericRegexCaptures,
    GenericEmits,
    MlBatchCalls,
    MlBatchCandidates,
    MlBatchCallsGe64,
    MlBatchCandidatesGe64,
    DecodeExtractNs,
    GenericPrefilterNs,
    GenericExtractNs,
    Phase2PrefilterHsScanNs,
    Phase2PrefilterDroppedHostNs,
    MlFeatureNs,
    MlScoreNs,
    DecodeDerivedBytes,
    HardwareCycles,
    HardwareInstructions,
    HardwareCacheReferences,
    HardwareCacheMisses,
    HardwareBranchInstructions,
    HardwareBranchMisses,
    HardwareStalledCyclesFrontend,
    HardwareStalledCyclesBackend,
    SchedulerVoluntaryContextSwitches,
    SchedulerInvoluntaryContextSwitches,
    SchedulerCpuMigrations,
    SchedulerDelayNs,
    GpuDispatchCalls,
    GpuUploadBytes,
    GpuReadbackBytes,
    GpuUploadNs,
    GpuReadbackNs,
    GpuSubmitToCompleteNs,
    GpuKernelNs,
    GpuQueueWaitNs,
    GpuAllocCalls,
    GpuAllocBytes,
    GpuFreeBytes,
    GpuCompileCalls,
    GpuCompileNs,
    GpuPipelineCacheHits,
    GpuPipelineCacheMisses,
    GpuFaults,
    GpuRetries,
    GpuRecoveries,
    GpuResidualBatches,
    GpuOverlapNs,
    AllocationCount,
    DeallocationCount,
    AllocationBytes,
    DeallocationBytes,
    MinorFaults,
    MajorFaults,
    IoReadBytes,
    IoWriteBytes,
    IoReadSyscalls,
    IoWriteSyscalls,
    IoCancelledWriteBytes,
    NetworkBytesRead,
    NetworkBytesWritten,
    NetworkRequests,
    NetworkRetries,
    PageCacheColdObservations,
    PageCacheWarmObservations,
    PageCacheDirectObservations,
    FilesScanned,
    BytesScanned,
    SkippedFiles,
    MatchesFound,
    StructuredParseFailures,
    StructuredOversizeSkips,
    DecodeTruncations,
    DecodeOversizeSkips,
    InvalidPatternIndexSkips,
    BoundaryResultCardinalityMismatches,
    BoundarySeamTruncations,
    LineOffsetMappingMismatches,
    ChunkDeadlineAborts,
    BinaryStringsNamedExclusions,
    SkippedOverMaxSize,
    SkippedBinary,
    SkippedExcluded,
    SkippedUnreadable,
    GitObjectUnreadable,
    SkippedArchiveTruncated,
    BinarySectionNameUnresolved,
    SourceTruncated,
    StructuredSourceParseFailures,
    ArchiveDuplicateScanUnavailable,
    GitLfsPointer,
    VendoredPathSuppressions,
    ExampleSuppressions,
    BinaryGhidraDegradedToStrings,
    BinaryUnreadable,
    GpuMatcherNs,
    GpuCoalesceNs,
    GpuDispatchNs,
    GpuDeriveNs,
    GpuRecallFloorNs,
    Phase2GpuAdmissionNs,
    GpuCoalescedBytes,
    GpuMaxDispatchBytes,
    GpuPresenceBits,
    GpuUnderfireRecovered,
    GpuTriggerBits,
    Phase2GpuAdmitted,
    Phase2GpuEvidenceBits,
    Phase2GpuHaystackUploads,
    Phase2GpuCompleteChunks,
    Phase2GpuCompleteRows,
    Phase2GpuExcludedOversized,
    Phase2GpuExcludedNonAscii,
    Phase2AlwaysAnchorChunks,
    Phase2AlwaysAnchorCandidateRows,
    Phase2AlwaysAnchorCandidateCount,
    ConfirmedAnchorCandidateRows,
    ConfirmedAnchorCandidateCount,
    GenericKeywordCandidateRows,
    GenericKeywordCandidateCount,
    ConfirmedSuffixGateNs,
    ConfirmedSuffixGateCalls,
    ConfirmedSuffixGateSkips,
    ConfirmedCompanionGateNs,
    ConfirmedCompanionGateCalls,
    ConfirmedCompanionGateDenials,
    ConfirmedAnchorCollectNs,
    ConfirmedAnchorCollectCalls,
    ConfirmedExtractNs,
    ConfirmedExtractCalls,
    ConfirmedAnchoredMatches,
    ConfirmedWholeChunkMatches,
    ConfirmedHotDirectFilterSkips,
    PostprocessFragmentsNs,
    PostprocessFragmentsCalls,
    PostprocessFragmentsCandidates,
    PostprocessFragmentsMatches,
    PostprocessDedupNs,
    PostprocessDedupCalls,
    Phase2AnchorCollectNs,
    Phase2AnchorCollectCalls,
    Phase2AnchoredVerifyCandidates,
    Phase2AnchoredVerifyMatches,
    Phase2WholeChunkPatterns,
    Phase2WholeChunkMatches,
}
impl CounterId {
    pub const ALL: [Self; 157] = [
        Self::InputBytes,
        Self::InputUnits,
        Self::ProcessCpuTime,
        Self::Phase2PrefilterMarkCalls,
        Self::Phase2PrefilterGateSkips,
        Self::Phase2PrefilterPerPatternWork,
        Self::Phase2PrefilterHsServed,
        Self::Phase2PrefilterRegexsetServed,
        Self::DecodeParentChunks,
        Self::DecodeDerivedChunks,
        Self::DecodeExtractCalls,
        Self::DecodeExtractBytes,
        Self::GenericPrefilterCalls,
        Self::GenericKeywordLines,
        Self::GenericRegexCaptures,
        Self::GenericEmits,
        Self::MlBatchCalls,
        Self::MlBatchCandidates,
        Self::MlBatchCallsGe64,
        Self::MlBatchCandidatesGe64,
        Self::DecodeExtractNs,
        Self::GenericPrefilterNs,
        Self::GenericExtractNs,
        Self::Phase2PrefilterHsScanNs,
        Self::Phase2PrefilterDroppedHostNs,
        Self::MlFeatureNs,
        Self::MlScoreNs,
        Self::DecodeDerivedBytes,
        Self::HardwareCycles,
        Self::HardwareInstructions,
        Self::HardwareCacheReferences,
        Self::HardwareCacheMisses,
        Self::HardwareBranchInstructions,
        Self::HardwareBranchMisses,
        Self::HardwareStalledCyclesFrontend,
        Self::HardwareStalledCyclesBackend,
        Self::SchedulerVoluntaryContextSwitches,
        Self::SchedulerInvoluntaryContextSwitches,
        Self::SchedulerCpuMigrations,
        Self::SchedulerDelayNs,
        Self::GpuDispatchCalls,
        Self::GpuUploadBytes,
        Self::GpuReadbackBytes,
        Self::GpuUploadNs,
        Self::GpuReadbackNs,
        Self::GpuSubmitToCompleteNs,
        Self::GpuKernelNs,
        Self::GpuQueueWaitNs,
        Self::GpuAllocCalls,
        Self::GpuAllocBytes,
        Self::GpuFreeBytes,
        Self::GpuCompileCalls,
        Self::GpuCompileNs,
        Self::GpuPipelineCacheHits,
        Self::GpuPipelineCacheMisses,
        Self::GpuFaults,
        Self::GpuRetries,
        Self::GpuRecoveries,
        Self::GpuResidualBatches,
        Self::GpuOverlapNs,
        Self::AllocationCount,
        Self::DeallocationCount,
        Self::AllocationBytes,
        Self::DeallocationBytes,
        Self::MinorFaults,
        Self::MajorFaults,
        Self::IoReadBytes,
        Self::IoWriteBytes,
        Self::IoReadSyscalls,
        Self::IoWriteSyscalls,
        Self::IoCancelledWriteBytes,
        Self::NetworkBytesRead,
        Self::NetworkBytesWritten,
        Self::NetworkRequests,
        Self::NetworkRetries,
        Self::PageCacheColdObservations,
        Self::PageCacheWarmObservations,
        Self::PageCacheDirectObservations,
        Self::FilesScanned,
        Self::BytesScanned,
        Self::SkippedFiles,
        Self::MatchesFound,
        Self::StructuredParseFailures,
        Self::StructuredOversizeSkips,
        Self::DecodeTruncations,
        Self::DecodeOversizeSkips,
        Self::InvalidPatternIndexSkips,
        Self::BoundaryResultCardinalityMismatches,
        Self::BoundarySeamTruncations,
        Self::LineOffsetMappingMismatches,
        Self::ChunkDeadlineAborts,
        Self::BinaryStringsNamedExclusions,
        Self::SkippedOverMaxSize,
        Self::SkippedBinary,
        Self::SkippedExcluded,
        Self::SkippedUnreadable,
        Self::GitObjectUnreadable,
        Self::SkippedArchiveTruncated,
        Self::BinarySectionNameUnresolved,
        Self::SourceTruncated,
        Self::StructuredSourceParseFailures,
        Self::ArchiveDuplicateScanUnavailable,
        Self::GitLfsPointer,
        Self::VendoredPathSuppressions,
        Self::ExampleSuppressions,
        Self::BinaryGhidraDegradedToStrings,
        Self::BinaryUnreadable,
        Self::GpuMatcherNs,
        Self::GpuCoalesceNs,
        Self::GpuDispatchNs,
        Self::GpuDeriveNs,
        Self::GpuRecallFloorNs,
        Self::Phase2GpuAdmissionNs,
        Self::GpuCoalescedBytes,
        Self::GpuMaxDispatchBytes,
        Self::GpuPresenceBits,
        Self::GpuUnderfireRecovered,
        Self::GpuTriggerBits,
        Self::Phase2GpuAdmitted,
        Self::Phase2GpuEvidenceBits,
        Self::Phase2GpuHaystackUploads,
        Self::Phase2GpuCompleteChunks,
        Self::Phase2GpuCompleteRows,
        Self::Phase2GpuExcludedOversized,
        Self::Phase2GpuExcludedNonAscii,
        Self::Phase2AlwaysAnchorChunks,
        Self::Phase2AlwaysAnchorCandidateRows,
        Self::Phase2AlwaysAnchorCandidateCount,
        Self::ConfirmedAnchorCandidateRows,
        Self::ConfirmedAnchorCandidateCount,
        Self::GenericKeywordCandidateRows,
        Self::GenericKeywordCandidateCount,
        Self::ConfirmedSuffixGateNs,
        Self::ConfirmedSuffixGateCalls,
        Self::ConfirmedSuffixGateSkips,
        Self::ConfirmedCompanionGateNs,
        Self::ConfirmedCompanionGateCalls,
        Self::ConfirmedCompanionGateDenials,
        Self::ConfirmedAnchorCollectNs,
        Self::ConfirmedAnchorCollectCalls,
        Self::ConfirmedExtractNs,
        Self::ConfirmedExtractCalls,
        Self::ConfirmedAnchoredMatches,
        Self::ConfirmedWholeChunkMatches,
        Self::ConfirmedHotDirectFilterSkips,
        Self::PostprocessFragmentsNs,
        Self::PostprocessFragmentsCalls,
        Self::PostprocessFragmentsCandidates,
        Self::PostprocessFragmentsMatches,
        Self::PostprocessDedupNs,
        Self::PostprocessDedupCalls,
        Self::Phase2AnchorCollectNs,
        Self::Phase2AnchorCollectCalls,
        Self::Phase2AnchoredVerifyCandidates,
        Self::Phase2AnchoredVerifyMatches,
        Self::Phase2WholeChunkPatterns,
        Self::Phase2WholeChunkMatches,
    ];

    pub const fn metric_id(self) -> MetricId {
        match self {
            Self::InputBytes => MetricId::InputBytes,
            Self::InputUnits => MetricId::InputUnits,
            Self::ProcessCpuTime => MetricId::ProcessCpuTime,
            Self::Phase2PrefilterMarkCalls => MetricId::Phase2PrefilterMarkCalls,
            Self::Phase2PrefilterGateSkips => MetricId::Phase2PrefilterGateSkips,
            Self::Phase2PrefilterPerPatternWork => MetricId::Phase2PrefilterPerPatternWork,
            Self::Phase2PrefilterHsServed => MetricId::Phase2PrefilterHsServed,
            Self::Phase2PrefilterRegexsetServed => MetricId::Phase2PrefilterRegexsetServed,
            Self::DecodeParentChunks => MetricId::DecodeParentChunks,
            Self::DecodeDerivedChunks => MetricId::DecodeDerivedChunks,
            Self::DecodeExtractCalls => MetricId::DecodeExtractCalls,
            Self::DecodeExtractBytes => MetricId::DecodeExtractBytes,
            Self::GenericPrefilterCalls => MetricId::GenericPrefilterCalls,
            Self::GenericKeywordLines => MetricId::GenericKeywordLines,
            Self::GenericRegexCaptures => MetricId::GenericRegexCaptures,
            Self::GenericEmits => MetricId::GenericEmits,
            Self::MlBatchCalls => MetricId::MlBatchCalls,
            Self::MlBatchCandidates => MetricId::MlBatchCandidates,
            Self::MlBatchCallsGe64 => MetricId::MlBatchCallsGe64,
            Self::MlBatchCandidatesGe64 => MetricId::MlBatchCandidatesGe64,
            Self::DecodeExtractNs => MetricId::DecodeExtractNs,
            Self::GenericPrefilterNs => MetricId::GenericPrefilterNs,
            Self::GenericExtractNs => MetricId::GenericExtractNs,
            Self::Phase2PrefilterHsScanNs => MetricId::Phase2PrefilterHsScanNs,
            Self::Phase2PrefilterDroppedHostNs => MetricId::Phase2PrefilterDroppedHostNs,
            Self::MlFeatureNs => MetricId::MlFeatureNs,
            Self::MlScoreNs => MetricId::MlScoreNs,
            Self::DecodeDerivedBytes => MetricId::DecodeDerivedBytes,
            Self::HardwareCycles => MetricId::HardwareCycles,
            Self::HardwareInstructions => MetricId::HardwareInstructions,
            Self::HardwareCacheReferences => MetricId::HardwareCacheReferences,
            Self::HardwareCacheMisses => MetricId::HardwareCacheMisses,
            Self::HardwareBranchInstructions => MetricId::HardwareBranchInstructions,
            Self::HardwareBranchMisses => MetricId::HardwareBranchMisses,
            Self::HardwareStalledCyclesFrontend => MetricId::HardwareStalledCyclesFrontend,
            Self::HardwareStalledCyclesBackend => MetricId::HardwareStalledCyclesBackend,
            Self::SchedulerVoluntaryContextSwitches => MetricId::SchedulerVoluntaryContextSwitches,
            Self::SchedulerInvoluntaryContextSwitches => {
                MetricId::SchedulerInvoluntaryContextSwitches
            }
            Self::SchedulerCpuMigrations => MetricId::SchedulerCpuMigrations,
            Self::SchedulerDelayNs => MetricId::SchedulerDelayNs,
            Self::GpuDispatchCalls => MetricId::GpuDispatchCalls,
            Self::GpuUploadBytes => MetricId::GpuUploadBytes,
            Self::GpuReadbackBytes => MetricId::GpuReadbackBytes,
            Self::GpuUploadNs => MetricId::GpuUploadNs,
            Self::GpuReadbackNs => MetricId::GpuReadbackNs,
            Self::GpuSubmitToCompleteNs => MetricId::GpuSubmitToCompleteNs,
            Self::GpuKernelNs => MetricId::GpuKernelNs,
            Self::GpuQueueWaitNs => MetricId::GpuQueueWaitNs,
            Self::GpuAllocCalls => MetricId::GpuAllocCalls,
            Self::GpuAllocBytes => MetricId::GpuAllocBytes,
            Self::GpuFreeBytes => MetricId::GpuFreeBytes,
            Self::GpuCompileCalls => MetricId::GpuCompileCalls,
            Self::GpuCompileNs => MetricId::GpuCompileNs,
            Self::GpuPipelineCacheHits => MetricId::GpuPipelineCacheHits,
            Self::GpuPipelineCacheMisses => MetricId::GpuPipelineCacheMisses,
            Self::GpuFaults => MetricId::GpuFaults,
            Self::GpuRetries => MetricId::GpuRetries,
            Self::GpuRecoveries => MetricId::GpuRecoveries,
            Self::GpuResidualBatches => MetricId::GpuResidualBatches,
            Self::GpuOverlapNs => MetricId::GpuOverlapNs,
            Self::AllocationCount => MetricId::AllocationCount,
            Self::DeallocationCount => MetricId::DeallocationCount,
            Self::AllocationBytes => MetricId::AllocationBytes,
            Self::DeallocationBytes => MetricId::DeallocationBytes,
            Self::MinorFaults => MetricId::MinorFaults,
            Self::MajorFaults => MetricId::MajorFaults,
            Self::IoReadBytes => MetricId::IoReadBytes,
            Self::IoWriteBytes => MetricId::IoWriteBytes,
            Self::IoReadSyscalls => MetricId::IoReadSyscalls,
            Self::IoWriteSyscalls => MetricId::IoWriteSyscalls,
            Self::IoCancelledWriteBytes => MetricId::IoCancelledWriteBytes,
            Self::NetworkBytesRead => MetricId::NetworkBytesRead,
            Self::NetworkBytesWritten => MetricId::NetworkBytesWritten,
            Self::NetworkRequests => MetricId::NetworkRequests,
            Self::NetworkRetries => MetricId::NetworkRetries,
            Self::PageCacheColdObservations => MetricId::PageCacheColdObservations,
            Self::PageCacheWarmObservations => MetricId::PageCacheWarmObservations,
            Self::PageCacheDirectObservations => MetricId::PageCacheDirectObservations,
            Self::FilesScanned => MetricId::FilesScanned,
            Self::BytesScanned => MetricId::BytesScanned,
            Self::SkippedFiles => MetricId::SkippedFiles,
            Self::MatchesFound => MetricId::MatchesFound,
            Self::StructuredParseFailures => MetricId::StructuredParseFailures,
            Self::StructuredOversizeSkips => MetricId::StructuredOversizeSkips,
            Self::DecodeTruncations => MetricId::DecodeTruncations,
            Self::DecodeOversizeSkips => MetricId::DecodeOversizeSkips,
            Self::InvalidPatternIndexSkips => MetricId::InvalidPatternIndexSkips,
            Self::BoundaryResultCardinalityMismatches => {
                MetricId::BoundaryResultCardinalityMismatches
            }
            Self::BoundarySeamTruncations => MetricId::BoundarySeamTruncations,
            Self::LineOffsetMappingMismatches => MetricId::LineOffsetMappingMismatches,
            Self::ChunkDeadlineAborts => MetricId::ChunkDeadlineAborts,
            Self::BinaryStringsNamedExclusions => MetricId::BinaryStringsNamedExclusions,
            Self::SkippedOverMaxSize => MetricId::SkippedOverMaxSize,
            Self::SkippedBinary => MetricId::SkippedBinary,
            Self::SkippedExcluded => MetricId::SkippedExcluded,
            Self::SkippedUnreadable => MetricId::SkippedUnreadable,
            Self::GitObjectUnreadable => MetricId::GitObjectUnreadable,
            Self::SkippedArchiveTruncated => MetricId::SkippedArchiveTruncated,
            Self::BinarySectionNameUnresolved => MetricId::BinarySectionNameUnresolved,
            Self::SourceTruncated => MetricId::SourceTruncated,
            Self::StructuredSourceParseFailures => MetricId::StructuredSourceParseFailures,
            Self::ArchiveDuplicateScanUnavailable => MetricId::ArchiveDuplicateScanUnavailable,
            Self::GitLfsPointer => MetricId::GitLfsPointer,
            Self::VendoredPathSuppressions => MetricId::VendoredPathSuppressions,
            Self::ExampleSuppressions => MetricId::ExampleSuppressions,
            Self::BinaryGhidraDegradedToStrings => MetricId::BinaryGhidraDegradedToStrings,
            Self::BinaryUnreadable => MetricId::BinaryUnreadable,
            Self::GpuMatcherNs => MetricId::GpuMatcherNs,
            Self::GpuCoalesceNs => MetricId::GpuCoalesceNs,
            Self::GpuDispatchNs => MetricId::GpuDispatchNs,
            Self::GpuDeriveNs => MetricId::GpuDeriveNs,
            Self::GpuRecallFloorNs => MetricId::GpuRecallFloorNs,
            Self::Phase2GpuAdmissionNs => MetricId::Phase2GpuAdmissionNs,
            Self::GpuCoalescedBytes => MetricId::GpuCoalescedBytes,
            Self::GpuMaxDispatchBytes => MetricId::GpuMaxDispatchBytes,
            Self::GpuPresenceBits => MetricId::GpuPresenceBits,
            Self::GpuUnderfireRecovered => MetricId::GpuUnderfireRecovered,
            Self::GpuTriggerBits => MetricId::GpuTriggerBits,
            Self::Phase2GpuAdmitted => MetricId::Phase2GpuAdmitted,
            Self::Phase2GpuEvidenceBits => MetricId::Phase2GpuEvidenceBits,
            Self::Phase2GpuHaystackUploads => MetricId::Phase2GpuHaystackUploads,
            Self::Phase2GpuCompleteChunks => MetricId::Phase2GpuCompleteChunks,
            Self::Phase2GpuCompleteRows => MetricId::Phase2GpuCompleteRows,
            Self::Phase2GpuExcludedOversized => MetricId::Phase2GpuExcludedOversized,
            Self::Phase2GpuExcludedNonAscii => MetricId::Phase2GpuExcludedNonAscii,
            Self::Phase2AlwaysAnchorChunks => MetricId::Phase2AlwaysAnchorChunks,
            Self::Phase2AlwaysAnchorCandidateRows => MetricId::Phase2AlwaysAnchorCandidateRows,
            Self::Phase2AlwaysAnchorCandidateCount => MetricId::Phase2AlwaysAnchorCandidateCount,
            Self::ConfirmedAnchorCandidateRows => MetricId::ConfirmedAnchorCandidateRows,
            Self::ConfirmedAnchorCandidateCount => MetricId::ConfirmedAnchorCandidateCount,
            Self::GenericKeywordCandidateRows => MetricId::GenericKeywordCandidateRows,
            Self::GenericKeywordCandidateCount => MetricId::GenericKeywordCandidateCount,
            Self::ConfirmedSuffixGateNs => MetricId::ConfirmedSuffixGateNs,
            Self::ConfirmedSuffixGateCalls => MetricId::ConfirmedSuffixGateCalls,
            Self::ConfirmedSuffixGateSkips => MetricId::ConfirmedSuffixGateSkips,
            Self::ConfirmedCompanionGateNs => MetricId::ConfirmedCompanionGateNs,
            Self::ConfirmedCompanionGateCalls => MetricId::ConfirmedCompanionGateCalls,
            Self::ConfirmedCompanionGateDenials => MetricId::ConfirmedCompanionGateDenials,
            Self::ConfirmedAnchorCollectNs => MetricId::ConfirmedAnchorCollectNs,
            Self::ConfirmedAnchorCollectCalls => MetricId::ConfirmedAnchorCollectCalls,
            Self::ConfirmedExtractNs => MetricId::ConfirmedExtractNs,
            Self::ConfirmedExtractCalls => MetricId::ConfirmedExtractCalls,
            Self::ConfirmedAnchoredMatches => MetricId::ConfirmedAnchoredMatches,
            Self::ConfirmedWholeChunkMatches => MetricId::ConfirmedWholeChunkMatches,
            Self::ConfirmedHotDirectFilterSkips => MetricId::ConfirmedHotDirectFilterSkips,
            Self::PostprocessFragmentsNs => MetricId::PostprocessFragmentsNs,
            Self::PostprocessFragmentsCalls => MetricId::PostprocessFragmentsCalls,
            Self::PostprocessFragmentsCandidates => MetricId::PostprocessFragmentsCandidates,
            Self::PostprocessFragmentsMatches => MetricId::PostprocessFragmentsMatches,
            Self::PostprocessDedupNs => MetricId::PostprocessDedupNs,
            Self::PostprocessDedupCalls => MetricId::PostprocessDedupCalls,
            Self::Phase2AnchorCollectNs => MetricId::Phase2AnchorCollectNs,
            Self::Phase2AnchorCollectCalls => MetricId::Phase2AnchorCollectCalls,
            Self::Phase2AnchoredVerifyCandidates => MetricId::Phase2AnchoredVerifyCandidates,
            Self::Phase2AnchoredVerifyMatches => MetricId::Phase2AnchoredVerifyMatches,
            Self::Phase2WholeChunkPatterns => MetricId::Phase2WholeChunkPatterns,
            Self::Phase2WholeChunkMatches => MetricId::Phase2WholeChunkMatches,
        }
    }
}

/// Type-safe identifier for a latest-value metric.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum GaugeId {
    ResidentMemory = 0,
    VirtualMemory,
    ProcessThreads,
    GpuResidentBytes,
    GpuPeakResidentBytes,
    AllocationLiveBytes,
    AllocationPeakLiveBytes,
    ResidentHighWaterBytes,
    RetainedBufferBytes,
    RetainedBufferPeakBytes,
    GitBufferedBlobChunks,
}

impl GaugeId {
    pub const ALL: [Self; 11] = [
        Self::ResidentMemory,
        Self::VirtualMemory,
        Self::ProcessThreads,
        Self::GpuResidentBytes,
        Self::GpuPeakResidentBytes,
        Self::AllocationLiveBytes,
        Self::AllocationPeakLiveBytes,
        Self::ResidentHighWaterBytes,
        Self::RetainedBufferBytes,
        Self::RetainedBufferPeakBytes,
        Self::GitBufferedBlobChunks,
    ];

    pub const fn metric_id(self) -> MetricId {
        match self {
            Self::ResidentMemory => MetricId::ResidentMemory,
            Self::VirtualMemory => MetricId::VirtualMemory,
            Self::ProcessThreads => MetricId::ProcessThreads,
            Self::GpuResidentBytes => MetricId::GpuResidentBytes,
            Self::GpuPeakResidentBytes => MetricId::GpuPeakResidentBytes,
            Self::AllocationLiveBytes => MetricId::AllocationLiveBytes,
            Self::AllocationPeakLiveBytes => MetricId::AllocationPeakLiveBytes,
            Self::ResidentHighWaterBytes => MetricId::ResidentHighWaterBytes,
            Self::RetainedBufferBytes => MetricId::RetainedBufferBytes,
            Self::RetainedBufferPeakBytes => MetricId::RetainedBufferPeakBytes,
            Self::GitBufferedBlobChunks => MetricId::GitBufferedBlobChunks,
        }
    }
}

/// Stable identifier for an instantaneous causal event.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum EventId {
    BackendBatchCompleted = 0,
    BackendRecovered,
    CoverageGap,
    Interrupted,
    DetailedDiagnostic,
    GpuAdapterAcquired,
    GpuFault,
    GpuCapabilityUnsupported,
}

impl EventId {
    pub const COUNT: usize = 8;

    pub const fn index(self) -> usize {
        self as usize
    }
}

/// Bounded fixed set of queue slots for causality links and depth gauges.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum QueueId {
    SourceWork = 0,
    ScannerWork,
    DecoderWork,
    BackendBatch,
    LiveVerification,
    ResultMerge,
}

impl QueueId {
    /// Every queue slot in stable wire order.
    pub const ALL: [Self; 6] = [
        Self::SourceWork,
        Self::ScannerWork,
        Self::DecoderWork,
        Self::BackendBatch,
        Self::LiveVerification,
        Self::ResultMerge,
    ];

    pub const COUNT: usize = 6;

    pub const fn index(self) -> usize {
        self as usize
    }

    /// Stable text label used by profiles and operator reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceWork => "source-work",
            Self::ScannerWork => "scanner-work",
            Self::DecoderWork => "decoder-work",
            Self::BackendBatch => "backend-batch",
            Self::LiveVerification => "live-verification",
            Self::ResultMerge => "result-merge",
        }
    }
}

/// A reuse cache the profiler reports hit and miss counts for.
///
/// Every KeyHog cache that exists to avoid repeating work reports through this
/// one enum, so "what is our cache hit rate" has a single answer instead of one
/// per subsystem. Record every consultation with exactly one of
/// [`crate::record_cache_hit`] or [`crate::record_cache_miss`], so the reported
/// rate has a real denominator.
///
/// Counters are indexed by [`CacheId::index`] into a fixed array of length
/// [`CacheId::COUNT`], so recording is one relaxed atomic add with no
/// allocation and no lookup on the hot path.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum CacheId {
    /// Persisted autoroute backend decision reused instead of re-deciding.
    /// A miss means the scan runs without a calibrated route.
    AutorouteDecision = 0,
    /// Autoroute calibration measurement reused instead of re-measuring.
    AutorouteCalibration,
    /// Chunk skipped because the incremental scan judged it unchanged.
    IncrementalUnchanged,
    /// Compiled matcher artifact reused instead of recompiled. This is the
    /// cache standing between a scan and the engine-initialization cost.
    MatcherArtifact,
    /// Credential verification result reused instead of re-requested. A miss
    /// costs a network round trip, so this rate is also a rate-limit story.
    VerifierResult,
    /// Hyperscan compiled regex shard database reused from disk cache.
    HyperscanShard,
    /// Compiled GPU literal-set binary matcher reused from disk cache.
    GpuProgram,
    /// Pre-parsed detector JSON execution plan reused from cache.
    DetectorPlan,
}

impl CacheId {
    /// Every cache slot in stable wire order.
    pub const ALL: [Self; Self::COUNT] = [
        Self::AutorouteDecision,
        Self::AutorouteCalibration,
        Self::IncrementalUnchanged,
        Self::MatcherArtifact,
        Self::VerifierResult,
        Self::HyperscanShard,
        Self::GpuProgram,
        Self::DetectorPlan,
    ];

    /// Number of variants, and the length of the profiler's counter arrays.
    pub const COUNT: usize = 8;

    /// Dense index into the profiler's per-shard counter arrays.
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Stable text label used by profiles and operator reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutorouteDecision => "autoroute-decision",
            Self::AutorouteCalibration => "autoroute-calibration",
            Self::IncrementalUnchanged => "incremental-unchanged",
            Self::MatcherArtifact => "matcher-artifact",
            Self::VerifierResult => "verifier-result",
            Self::HyperscanShard => "hyperscan-shard",
            Self::GpuProgram => "gpu-program",
            Self::DetectorPlan => "detector-plan",
        }
    }
}
/// A compiler surface / artifact class that compiles matcher, plan, or execution policy data.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum CompileSurfaceId {
    /// Detector execution plans compiled from detector definitions.
    DetectorPlan = 0,
    /// Entropy policy tables compiled for detector thresholds.
    EntropyPolicy,
    /// Assignment keyword index compiled from secret and policy keywords.
    AssignmentKeywordMatcher,
    /// GPU literal matchers compiled from detector patterns.
    GpuLiterals,
    /// SIMD / Hyperscan regex database compiled from detector patterns.
    SimdProgram,
    /// Intermediate compile state and companion compilation.
    CompileState,
    /// Decode transformation policy compiled from detector specs.
    DecodePolicy,
    /// Checksum validator catalog and index compiled from validator specs.
    ValidatorCatalog,
    /// Match confidence policy compiled from detector specs.
    ConfidencePolicy,
    /// Credential shape rules compiled from detector specs.
    CredentialShapes,
    /// Detector execution policy compiled from detector specs.
    DetectorExecutionPolicy,
    /// Canonical hex key material policy compiled from detector specs.
    DetectorKeyMaterialPolicy,
    /// Detector ML policy compiled from detector specs.
    DetectorMlPolicy,
}

impl CompileSurfaceId {
    /// Number of distinct compile surface classes.
    pub const COUNT: usize = 13;

    /// Every compile surface in stable wire order.
    pub const ALL: [Self; Self::COUNT] = [
        Self::DetectorPlan,
        Self::EntropyPolicy,
        Self::AssignmentKeywordMatcher,
        Self::GpuLiterals,
        Self::SimdProgram,
        Self::CompileState,
        Self::DecodePolicy,
        Self::ValidatorCatalog,
        Self::ConfidencePolicy,
        Self::CredentialShapes,
        Self::DetectorExecutionPolicy,
        Self::DetectorKeyMaterialPolicy,
        Self::DetectorMlPolicy,
    ];

    /// Dense index into the profiler's compile-surface arrays.
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Stable text label used by profiles and operator reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DetectorPlan => "detector-plan",
            Self::EntropyPolicy => "entropy-policy",
            Self::AssignmentKeywordMatcher => "assignment-keyword-matcher",
            Self::GpuLiterals => "gpu-literals",
            Self::SimdProgram => "simd-program",
            Self::CompileState => "compile-state",
            Self::DecodePolicy => "decode-policy",
            Self::ValidatorCatalog => "validator-catalog",
            Self::ConfidencePolicy => "confidence-policy",
            Self::CredentialShapes => "credential-shapes",
            Self::DetectorExecutionPolicy => "detector-execution-policy",
            Self::DetectorKeyMaterialPolicy => "detector-key-material-policy",
            Self::DetectorMlPolicy => "detector-ml-policy",
        }
    }

    /// Canonical compile entry-point symbols for this surface class.
    pub const fn entry_points(self) -> &'static [&'static str] {
        match self {
            Self::DetectorPlan => &[
                "keyhog_scanner::detector_plan::CompiledDetectorPlans::compile",
                "keyhog_scanner::detector_plan::CompiledDetectorPlans::compile_with_decoder_plan",
                "keyhog_scanner::detector_plan::compile_detector_plan",
                "keyhog_scanner::detector_plan::compile_metadata",
                "keyhog_scanner::detector_plan::DetectorResolutionIndex::compile",
                "keyhog_scanner::detector_plan::CompiledDetectorRelationIndex::compile",
            ],
            Self::EntropyPolicy => &[
                "keyhog_scanner::entropy::policy::compile_entropy_policy",
                "keyhog_scanner::entropy::policy::compile_entropy_policy_with_length",
                "keyhog_scanner::entropy::policy::CompiledEntropyPolicy::compile",
                "keyhog_scanner::entropy::policy::CompiledEntropyPolicy::compile_with_length",
                "keyhog_scanner::entropy::policy::CompiledEntropyFloorPolicy::compile",
            ],
            Self::AssignmentKeywordMatcher => &[
                "keyhog_scanner::assignment_keyword_matcher::AssignmentKeywordMatcher::compile",
            ],
            Self::GpuLiterals => &[
                "keyhog_scanner::gpu_literal_artifacts::compile_gpu_literal_artifacts",
                "keyhog_scanner::gpu_literal_artifacts::compile_gpu_literal_artifact_plan",
                "keyhog_scanner::engine::gpu_lazy_helpers::compile_gpu_literals",
            ],
            Self::SimdProgram => &[
                "keyhog_scanner::simd::backend::HsScanner::compile_with_opts",
            ],
            Self::CompileState => &[
                "keyhog_scanner::compiler::compiler_build::build_compile_state",
                "keyhog_scanner::compiler::compiler_compile::compile_companion",
                "keyhog_scanner::compiler::compiler_compile::compile_detector_companions",
                "keyhog_scanner::compiler::compiler_compile::compile_pattern",
            ],
            Self::DecodePolicy => &[
                "keyhog_scanner::decode::policy::CompiledDecodeTransformPolicy::compile",
            ],
            Self::ValidatorCatalog => &[
                "keyhog_scanner::checksum::compiled::CompiledValidatorCatalog::compile",
                "keyhog_scanner::checksum::compiled::CompiledValidatorIndex::compile",
                "keyhog_scanner::checksum::compiled::CompiledDetectorValidators::compile",
            ],
            Self::ConfidencePolicy => &[
                "keyhog_scanner::confidence::policy::CompiledMatchConfidencePolicy::compile",
            ],
            Self::CredentialShapes => &[
                "keyhog_scanner::credential_shapes::compile_detector_shape_rule",
            ],
            Self::DetectorExecutionPolicy => &[
                "keyhog_scanner::detector_execution_policy::CompiledDetectorExecutionPolicy::compile",
            ],
            Self::DetectorKeyMaterialPolicy => &[
                "keyhog_scanner::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy::compile",
            ],
            Self::DetectorMlPolicy => &[
                "keyhog_scanner::detector_ml_policy::CompiledDetectorMlPolicy::compile",
            ],
        }
    }
}

/// Execution phase during which compilation occurred.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum CompilePhase {
    /// Compilation during installer generation (`keyhog install` or compile-execution-packs).
    Install = 0,
    /// Compilation during candidate update generation (`keyhog update`).
    Update,
    /// In-process compilation during scan execution.
    Scan,
    /// In-process compilation under explicit developer escape flag.
    Developer,
}

impl CompilePhase {
    /// Number of distinct compile phases.
    pub const COUNT: usize = 4;

    /// Every compile phase in stable wire order.
    pub const ALL: [Self; Self::COUNT] = [Self::Install, Self::Update, Self::Scan, Self::Developer];

    /// Dense index into compile phase arrays.
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Stable text label used by profiles and operator reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Update => "update",
            Self::Scan => "scan",
            Self::Developer => "developer",
        }
    }
}

/// Why one operation was attempted again.
///
/// A retry that fires is evidence of a defect, not a success, so every attempt
/// is counted and surfaced. There is deliberately no catch-all cause: an
/// unclassified failure is permanent and is not retried, which is what stops
/// "it will just retry" from becoming a reason to ship a racy path.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum RetryCause {
    /// A syscall returned EINTR.
    Interrupted = 0,
    /// A syscall returned EAGAIN or EWOULDBLOCK.
    WouldBlock,
    /// ENOENT or ESTALE on a path the walker had already enumerated.
    VanishedUnderWalk,
    /// The file was replaced, truncated, or grown between the size decision
    /// and the completion of the read.
    SizeChangedUnderRead,
    /// EBUSY, ETXTBSY, or a sharing violation.
    Locked,
    /// A 429 or an equivalent provider throttle.
    RateLimited,
    /// Connection reset, timeout, or name resolution failure.
    Network,
    /// A git pack was rewritten while it was being read.
    PackRewritten,
}

impl RetryCause {
    /// Every cause in stable wire order.
    pub const ALL: [Self; Self::COUNT] = [
        Self::Interrupted,
        Self::WouldBlock,
        Self::VanishedUnderWalk,
        Self::SizeChangedUnderRead,
        Self::Locked,
        Self::RateLimited,
        Self::Network,
        Self::PackRewritten,
    ];

    pub const COUNT: usize = 8;

    /// Dense index into the profiler's per-shard counter arrays.
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Stable text label used by profiles and operator reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupted => "interrupted",
            Self::WouldBlock => "would-block",
            Self::VanishedUnderWalk => "vanished-under-walk",
            Self::SizeChangedUnderRead => "size-changed-under-read",
            Self::Locked => "locked",
            Self::RateLimited => "rate-limited",
            Self::Network => "network",
            Self::PackRewritten => "pack-rewritten",
        }
    }
}

/// Number of slots in every indexed counter family.
///
/// Fixed so recording is one relaxed add with no bounds negotiation. A slot
/// outside the range is counted as dropped rather than folded into the last
/// slot, because a misattributed measurement is worse than a missing one.
pub const INDEXED_COUNTER_SLOTS: usize = 16;

/// An additive counter that exists once per caller-owned slot.
///
/// The caller owns the labels. A decoder registry knows slot three is base64,
/// so the profiler stores sixteen numbers and never a string, which is what
/// keeps the record path allocation-free and hash-free.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum IndexedCounterId {
    /// Nanoseconds spent inside one decoder slot.
    DecoderElapsedNs = 0,
    /// Sub-chunks one decoder slot produced.
    DecoderSubchunksEmitted,
}

impl IndexedCounterId {
    /// Every indexed family in stable wire order.
    pub const ALL: [Self; Self::COUNT] = [Self::DecoderElapsedNs, Self::DecoderSubchunksEmitted];

    pub const COUNT: usize = 2;

    pub const fn index(self) -> usize {
        self as usize
    }

    /// Stable text label used by profiles and operator reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DecoderElapsedNs => "decoder-elapsed-ns",
            Self::DecoderSubchunksEmitted => "decoder-subchunks-emitted",
        }
    }
}

/// Stable identifier for a numeric annotation attached to the run timeline.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum AnnotationId {
    DecodeDepth = 0,
    QueueDepth,
    WorkerIndex,
    RetryAttempt,
    GpuBackendKind,
    GpuAdapterVendor,
    GpuAdapterDevice,
    IoCacheState,
}

impl From<crate::Stage> for MetricId {
    fn from(stage: crate::Stage) -> Self {
        match stage {
            crate::Stage::SourceAcquire => Self::SourceAcquire,
            crate::Stage::SourceWalk => Self::SourceWalk,
            crate::Stage::SourceRead => Self::SourceRead,
            crate::Stage::Preprocess => Self::Preprocess,
            crate::Stage::Phase1Triggers => Self::Phase1Triggers,
            crate::Stage::BackendDispatch => Self::BackendDispatch,
            crate::Stage::HotPatterns => Self::HotPatterns,
            crate::Stage::ConfirmedPatterns => Self::ConfirmedPatterns,
            crate::Stage::Phase2Prefilter => Self::Phase2Prefilter,
            crate::Stage::Phase2KeywordAc => Self::Phase2KeywordAc,
            crate::Stage::Phase2SharedAc => Self::Phase2SharedAc,
            crate::Stage::Phase2AnchoredVerify => Self::Phase2AnchoredVerify,
            crate::Stage::Phase2WholeChunk => Self::Phase2WholeChunk,
            crate::Stage::GenericDetection => Self::GenericDetection,
            crate::Stage::Entropy => Self::Entropy,
            crate::Stage::MachineLearning => Self::MachineLearning,
            crate::Stage::Decode => Self::Decode,
            crate::Stage::Suppression => Self::Suppression,
            crate::Stage::LiveVerification => Self::LiveVerification,
            crate::Stage::Reporting => Self::Reporting,
            crate::Stage::SourceQueueWait => Self::SourceQueueWait,
            crate::Stage::IncrementalLookup => Self::IncrementalLookup,
            crate::Stage::BackendSelect => Self::BackendSelect,
            crate::Stage::ResultMerge => Self::ResultMerge,
            crate::Stage::ScannerQueueWait => Self::ScannerQueueWait,
            crate::Stage::AutorouteCalibration => Self::AutorouteCalibration,
            crate::Stage::BoundaryScan => Self::BoundaryScan,
            crate::Stage::DetectorLoad => Self::DetectorLoad,
            crate::Stage::DetectorValidate => Self::DetectorValidate,
            crate::Stage::ExecutionPackSelect => Self::ExecutionPackSelect,
            crate::Stage::ExecutionPackMap => Self::ExecutionPackMap,
            crate::Stage::BackendAcquire => Self::BackendAcquire,
            crate::Stage::BackendInit => Self::BackendInit,
            crate::Stage::Teardown => Self::Teardown,
            crate::Stage::ScanPipeline => Self::ScanPipeline,
            crate::Stage::ScannerCompile => Self::ScannerCompile,
        }
    }
}

/// Measurement behavior associated with a metric.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricKind {
    Counter,
    Duration,
    Gauge,
    Distribution,
}

/// Stable unit associated with a metric value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricUnit {
    Bytes,
    Count,
    Milliseconds,
    Nanoseconds,
}

/// Static metric metadata. Every string is embedded in the binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricDescriptor {
    pub id: MetricId,
    pub name: &'static str,
    pub kind: MetricKind,
    pub unit: MetricUnit,
}

const fn metric(
    id: MetricId,
    name: &'static str,
    kind: MetricKind,
    unit: MetricUnit,
) -> MetricDescriptor {
    MetricDescriptor {
        id,
        name,
        kind,
        unit,
    }
}

/// Allocation-free registry in numeric `MetricId` order.
pub static METRICS: [MetricDescriptor; MetricId::COUNT] = [
    metric(
        MetricId::SourceAcquire,
        "source-acquire",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::SourceWalk,
        "source-walk",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::SourceRead,
        "source-read",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::Preprocess,
        "preprocess",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::Phase1Triggers,
        "phase1-triggers",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::BackendDispatch,
        "backend-dispatch",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::HotPatterns,
        "hot-patterns",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::ConfirmedPatterns,
        "confirmed-patterns",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::Phase2Prefilter,
        "phase2-prefilter",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::Phase2KeywordAc,
        "phase2-keyword-ac",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::Phase2SharedAc,
        "phase2-shared-ac",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::Phase2AnchoredVerify,
        "phase2-anchored-verify",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::Phase2WholeChunk,
        "phase2-whole-chunk",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::GenericDetection,
        "generic-detection",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::Entropy,
        "entropy",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::MachineLearning,
        "machine-learning",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::Decode,
        "decode",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::Suppression,
        "suppression",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::LiveVerification,
        "live-verification",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::Reporting,
        "reporting",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::SourceQueueWait,
        "source-queue-wait",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::IncrementalLookup,
        "incremental-lookup",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::BackendSelect,
        "backend-select",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::ResultMerge,
        "result-merge",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::ScannerQueueWait,
        "scanner-queue-wait",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::InputBytes,
        "input-bytes",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::InputUnits,
        "input-units",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::WallTime,
        "wall-time",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::ProcessCpuTime,
        "process-cpu-time",
        MetricKind::Counter,
        MetricUnit::Milliseconds,
    ),
    metric(
        MetricId::ResidentMemory,
        "resident-memory",
        MetricKind::Gauge,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::VirtualMemory,
        "virtual-memory",
        MetricKind::Gauge,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::ProcessThreads,
        "process-threads",
        MetricKind::Gauge,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2PrefilterMarkCalls,
        "phase2-prefilter-mark-calls",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2PrefilterGateSkips,
        "phase2-prefilter-gate-skips",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2PrefilterPerPatternWork,
        "phase2-prefilter-per-pattern-work",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2PrefilterHsServed,
        "phase2-prefilter-hs-served",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2PrefilterRegexsetServed,
        "phase2-prefilter-regexset-served",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::DecodeParentChunks,
        "decode-parent-chunks",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::DecodeDerivedChunks,
        "decode-derived-chunks",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::DecodeExtractCalls,
        "decode-extract-calls",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::DecodeExtractBytes,
        "decode-extract-bytes",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::GenericPrefilterCalls,
        "generic-prefilter-calls",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GenericKeywordLines,
        "generic-keyword-lines",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GenericRegexCaptures,
        "generic-regex-captures",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GenericEmits,
        "generic-emits",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::MlBatchCalls,
        "ml-batch-calls",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::MlBatchCandidates,
        "ml-batch-candidates",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::MlBatchCallsGe64,
        "ml-batch-calls-ge64",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::MlBatchCandidatesGe64,
        "ml-batch-candidates-ge64",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::DecodeExtractNs,
        "decode-extract-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::GenericPrefilterNs,
        "generic-prefilter-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::GenericExtractNs,
        "generic-extract-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::Phase2PrefilterHsScanNs,
        "phase2-prefilter-hs-scan-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::Phase2PrefilterDroppedHostNs,
        "phase2-prefilter-dropped-host-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::MlFeatureNs,
        "ml-feature-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::MlScoreNs,
        "ml-score-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::MlBatchSize,
        "ml-batch-size",
        MetricKind::Distribution,
        MetricUnit::Count,
    ),
    metric(
        MetricId::DecodeDerivedBytes,
        "decode-derived-bytes",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::HardwareCycles,
        "hardware-cycles",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::HardwareInstructions,
        "hardware-instructions",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::HardwareCacheReferences,
        "hardware-cache-references",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::HardwareCacheMisses,
        "hardware-cache-misses",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::HardwareBranchInstructions,
        "hardware-branch-instructions",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::HardwareBranchMisses,
        "hardware-branch-misses",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::HardwareStalledCyclesFrontend,
        "hardware-stalled-cycles-frontend",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::HardwareStalledCyclesBackend,
        "hardware-stalled-cycles-backend",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::SchedulerVoluntaryContextSwitches,
        "scheduler-voluntary-context-switches",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::SchedulerInvoluntaryContextSwitches,
        "scheduler-involuntary-context-switches",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::SchedulerCpuMigrations,
        "scheduler-cpu-migrations",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::SchedulerDelayNs,
        "scheduler-delay-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::GpuDispatchCalls,
        "gpu-dispatch-calls",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GpuUploadBytes,
        "gpu-upload-bytes",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::GpuReadbackBytes,
        "gpu-readback-bytes",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::GpuUploadNs,
        "gpu-upload-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::GpuReadbackNs,
        "gpu-readback-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::GpuSubmitToCompleteNs,
        "gpu-submit-to-complete-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::GpuKernelNs,
        "gpu-kernel-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::GpuQueueWaitNs,
        "gpu-queue-wait-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::GpuAllocCalls,
        "gpu-alloc-calls",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GpuAllocBytes,
        "gpu-alloc-bytes",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::GpuFreeBytes,
        "gpu-free-bytes",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::GpuCompileCalls,
        "gpu-compile-calls",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GpuCompileNs,
        "gpu-compile-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::GpuPipelineCacheHits,
        "gpu-pipeline-cache-hits",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GpuPipelineCacheMisses,
        "gpu-pipeline-cache-misses",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GpuFaults,
        "gpu-faults",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GpuRetries,
        "gpu-retries",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GpuRecoveries,
        "gpu-recoveries",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GpuResidualBatches,
        "gpu-residual-batches",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GpuOverlapNs,
        "gpu-overlap-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::GpuResidentBytes,
        "gpu-resident-bytes",
        MetricKind::Gauge,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::GpuPeakResidentBytes,
        "gpu-peak-resident-bytes",
        MetricKind::Gauge,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::AllocationCount,
        "allocation-count",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::DeallocationCount,
        "deallocation-count",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::AllocationBytes,
        "allocation-bytes",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::DeallocationBytes,
        "deallocation-bytes",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::AllocationLiveBytes,
        "allocation-live-bytes",
        MetricKind::Gauge,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::AllocationPeakLiveBytes,
        "allocation-peak-live-bytes",
        MetricKind::Gauge,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::MinorFaults,
        "minor-faults",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::MajorFaults,
        "major-faults",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::IoReadBytes,
        "io-read-bytes",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::IoWriteBytes,
        "io-write-bytes",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::IoReadSyscalls,
        "io-read-syscalls",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::IoWriteSyscalls,
        "io-write-syscalls",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::IoCancelledWriteBytes,
        "io-cancelled-write-bytes",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::ResidentHighWaterBytes,
        "resident-high-water-bytes",
        MetricKind::Gauge,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::RetainedBufferBytes,
        "retained-buffer-bytes",
        MetricKind::Gauge,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::RetainedBufferPeakBytes,
        "retained-buffer-peak-bytes",
        MetricKind::Gauge,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::NetworkBytesRead,
        "network-bytes-read",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::NetworkBytesWritten,
        "network-bytes-written",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::NetworkRequests,
        "network-requests",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::NetworkRetries,
        "network-retries",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::PageCacheColdObservations,
        "page-cache-cold-observations",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::PageCacheWarmObservations,
        "page-cache-warm-observations",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::PageCacheDirectObservations,
        "page-cache-direct-observations",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::FsOpenLatencyNs,
        "fs-open-latency-ns",
        MetricKind::Distribution,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::FsReadLatencyNs,
        "fs-read-latency-ns",
        MetricKind::Distribution,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::FsMetadataLatencyNs,
        "fs-metadata-latency-ns",
        MetricKind::Distribution,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::NetworkLatencyNs,
        "network-latency-ns",
        MetricKind::Distribution,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::AutorouteCalibration,
        "autoroute-calibration",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::BoundaryScan,
        "boundary-scan",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::DetectorLoad,
        "detector-load",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::DetectorValidate,
        "detector-validate",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::ExecutionPackSelect,
        "execution-pack-select",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::ExecutionPackMap,
        "execution-pack-map",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::BackendAcquire,
        "backend-acquire",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::BackendInit,
        "backend-init",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::Teardown,
        "teardown",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::ScanPipeline,
        "scan-pipeline",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::ScannerCompile,
        "scanner-compile",
        MetricKind::Duration,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::FilesScanned,
        "files-scanned",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::BytesScanned,
        "bytes-scanned",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::SkippedFiles,
        "skipped-files",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::MatchesFound,
        "matches-found",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::StructuredParseFailures,
        "structured-parse-failures",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::StructuredOversizeSkips,
        "structured-oversize-skips",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::DecodeTruncations,
        "decode-truncations",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::DecodeOversizeSkips,
        "decode-oversize-skips",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::InvalidPatternIndexSkips,
        "invalid-pattern-index-skips",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::BoundaryResultCardinalityMismatches,
        "boundary-result-cardinality-mismatches",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::BoundarySeamTruncations,
        "boundary-seam-truncations",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::LineOffsetMappingMismatches,
        "line-offset-mapping-mismatches",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::ChunkDeadlineAborts,
        "chunk-deadline-aborts",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::BinaryStringsNamedExclusions,
        "binary-strings-named-exclusions",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::SkippedOverMaxSize,
        "skipped-over-max-size",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::SkippedBinary,
        "skipped-binary",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::SkippedExcluded,
        "skipped-excluded",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::SkippedUnreadable,
        "skipped-unreadable",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GitObjectUnreadable,
        "git-object-unreadable",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::SkippedArchiveTruncated,
        "skipped-archive-truncated",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::BinarySectionNameUnresolved,
        "binary-section-name-unresolved",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::SourceTruncated,
        "source-truncated",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::StructuredSourceParseFailures,
        "structured-source-parse-failures",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::ArchiveDuplicateScanUnavailable,
        "archive-duplicate-scan-unavailable",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GitLfsPointer,
        "git-lfs-pointer",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::VendoredPathSuppressions,
        "vendored-path-suppressions",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::ExampleSuppressions,
        "example-suppressions",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::BinaryGhidraDegradedToStrings,
        "binary-ghidra-degraded-to-strings",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::BinaryUnreadable,
        "binary-unreadable",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GitBufferedBlobChunks,
        "git-buffered-blob-chunks",
        MetricKind::Gauge,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GpuMatcherNs,
        "gpu-matcher-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::GpuCoalesceNs,
        "gpu-coalesce-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::GpuDispatchNs,
        "gpu-dispatch-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::GpuDeriveNs,
        "gpu-derive-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::GpuRecallFloorNs,
        "gpu-recall-floor-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::Phase2GpuAdmissionNs,
        "phase2-gpu-admission-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::GpuCoalescedBytes,
        "gpu-coalesced-bytes",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::GpuMaxDispatchBytes,
        "gpu-max-dispatch-bytes",
        MetricKind::Counter,
        MetricUnit::Bytes,
    ),
    metric(
        MetricId::GpuPresenceBits,
        "gpu-presence-bits",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GpuUnderfireRecovered,
        "gpu-underfire-recovered",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GpuTriggerBits,
        "gpu-trigger-bits",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2GpuAdmitted,
        "phase2-gpu-admitted",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2GpuEvidenceBits,
        "phase2-gpu-evidence-bits",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2GpuHaystackUploads,
        "phase2-gpu-haystack-uploads",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2GpuCompleteChunks,
        "phase2-gpu-complete-chunks",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2GpuCompleteRows,
        "phase2-gpu-complete-rows",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2GpuExcludedOversized,
        "phase2-gpu-excluded-oversized",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2GpuExcludedNonAscii,
        "phase2-gpu-excluded-non-ascii",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2AlwaysAnchorChunks,
        "phase2-always-anchor-chunks",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2AlwaysAnchorCandidateRows,
        "phase2-always-anchor-candidate-rows",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2AlwaysAnchorCandidateCount,
        "phase2-always-anchor-candidate-count",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::ConfirmedAnchorCandidateRows,
        "confirmed-anchor-candidate-rows",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::ConfirmedAnchorCandidateCount,
        "confirmed-anchor-candidate-count",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GenericKeywordCandidateRows,
        "generic-keyword-candidate-rows",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::GenericKeywordCandidateCount,
        "generic-keyword-candidate-count",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::ConfirmedSuffixGateNs,
        "confirmed-suffix-gate-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::ConfirmedSuffixGateCalls,
        "confirmed-suffix-gate-calls",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::ConfirmedSuffixGateSkips,
        "confirmed-suffix-gate-skips",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::ConfirmedCompanionGateNs,
        "confirmed-companion-gate-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::ConfirmedCompanionGateCalls,
        "confirmed-companion-gate-calls",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::ConfirmedCompanionGateDenials,
        "confirmed-companion-gate-denials",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::ConfirmedAnchorCollectNs,
        "confirmed-anchor-collect-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::ConfirmedAnchorCollectCalls,
        "confirmed-anchor-collect-calls",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::ConfirmedExtractNs,
        "confirmed-extract-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::ConfirmedExtractCalls,
        "confirmed-extract-calls",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::ConfirmedAnchoredMatches,
        "confirmed-anchored-matches",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::ConfirmedWholeChunkMatches,
        "confirmed-whole-chunk-matches",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::ConfirmedHotDirectFilterSkips,
        "confirmed-hot-direct-filter-skips",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::PostprocessFragmentsNs,
        "postprocess-fragments-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::PostprocessFragmentsCalls,
        "postprocess-fragments-calls",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::PostprocessFragmentsCandidates,
        "postprocess-fragments-candidates",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::PostprocessFragmentsMatches,
        "postprocess-fragments-matches",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::PostprocessDedupNs,
        "postprocess-dedup-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::PostprocessDedupCalls,
        "postprocess-dedup-calls",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2AnchorCollectNs,
        "phase2-anchor-collect-ns",
        MetricKind::Counter,
        MetricUnit::Nanoseconds,
    ),
    metric(
        MetricId::Phase2AnchorCollectCalls,
        "phase2-anchor-collect-calls",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2AnchoredVerifyCandidates,
        "phase2-anchored-verify-candidates",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2AnchoredVerifyMatches,
        "phase2-anchored-verify-matches",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2WholeChunkPatterns,
        "phase2-whole-chunk-patterns",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
    metric(
        MetricId::Phase2WholeChunkMatches,
        "phase2-whole-chunk-matches",
        MetricKind::Counter,
        MetricUnit::Count,
    ),
];

impl MetricId {
    pub const COUNT: usize = 210;
    #[inline]
    pub const fn descriptor(self) -> &'static MetricDescriptor {
        &METRICS[self as usize]
    }

    /// Stable metric name from the static registry.
    #[inline]
    pub const fn as_str(self) -> &'static str {
        self.descriptor().name
    }
}

/// Named GPU region dispatch phase timing counters.
pub const GPU_DISPATCH_PHASE_COUNTERS: [CounterId; 6] = [
    CounterId::GpuMatcherNs,
    CounterId::GpuCoalesceNs,
    CounterId::GpuDispatchNs,
    CounterId::GpuDeriveNs,
    CounterId::GpuRecallFloorNs,
    CounterId::Phase2GpuAdmissionNs,
];

/// Named GPU region dispatch decomposition counters whose sum composes the enclosing dispatch duration.
pub const GPU_DISPATCH_DECOMPOSITION_COUNTERS: [CounterId; 3] = [
    CounterId::GpuCoalesceNs,
    CounterId::GpuDispatchNs,
    CounterId::GpuDeriveNs,
];

/// Slice of all GPU dispatch phase timing counters.
pub fn gpu_dispatch_phase_counters() -> &'static [CounterId] {
    &GPU_DISPATCH_PHASE_COUNTERS
}

/// Slice of GPU dispatch decomposition timing counters.
pub fn gpu_dispatch_decomposition_counters() -> &'static [CounterId] {
    &GPU_DISPATCH_DECOMPOSITION_COUNTERS
}
