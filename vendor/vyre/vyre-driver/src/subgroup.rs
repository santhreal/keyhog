//! Backend-neutral subgroup operation taxonomy.

/// Canonical subgroup intrinsic operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubgroupOp {
    /// Broadcast a value from one subgroup lane to all lanes.
    Broadcast,
    /// Reduce add across the subgroup.
    Add,
    /// Reduce max across the subgroup.
    Max,
    /// Reduce min across the subgroup.
    Min,
    /// Inclusive scan add across the subgroup.
    InclusiveAdd,
    /// Exclusive scan add across the subgroup.
    ExclusiveAdd,
    /// Shuffle-xor butterfly swap.
    ShuffleXor,
}

impl SubgroupOp {
    /// Iterate every canonical operation.
    #[must_use]
    pub const fn all() -> &'static [SubgroupOp] {
        &[
            SubgroupOp::Broadcast,
            SubgroupOp::Add,
            SubgroupOp::Max,
            SubgroupOp::Min,
            SubgroupOp::InclusiveAdd,
            SubgroupOp::ExclusiveAdd,
            SubgroupOp::ShuffleXor,
        ]
    }
}

/// Subgroup capability record shared by validation and optimizers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SubgroupCaps {
    /// Native subgroup operations are available for compute.
    pub supports_subgroup: bool,
    /// Subgroup operations are available in vertex-stage contexts.
    pub supports_subgroup_vertex: bool,
    /// Subgroup size in lanes; `0` means unknown.
    pub subgroup_size: u32,
}

impl SubgroupCaps {
    /// Capability record for native subgroup intrinsics.
    #[must_use]
    pub const fn native(subgroup_size: u32) -> Self {
        Self {
            supports_subgroup: true,
            supports_subgroup_vertex: false,
            subgroup_size,
        }
    }

    /// Capability record from a feature bit and reported lane-size range.
    #[must_use]
    pub const fn from_feature_range(
        supports_feature: bool,
        supports_vertex_stage: bool,
        min_size: u32,
        max_size: u32,
    ) -> Self {
        let supports_subgroup = supports_feature && min_size > 0 && max_size >= min_size;
        Self {
            supports_subgroup,
            supports_subgroup_vertex: supports_vertex_stage && supports_subgroup,
            subgroup_size: if supports_subgroup { min_size } else { 0 },
        }
    }

    /// Return true when native subgroup operations are usable.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        self.supports_subgroup && self.subgroup_size > 0
    }
}

/// Canonical lane offsets for a power-of-two full-subgroup tree reduction.
#[must_use]
pub fn reduction_offsets(subgroup_size: u32) -> Vec<u32> {
    let mut offsets = Vec::with_capacity(if subgroup_size == 0 {
        0
    } else {
        subgroup_size.ilog2() as usize
    });
    reduction_offsets_into(subgroup_size, &mut offsets);
    offsets
}

/// Write canonical reduction offsets into caller-owned storage.
pub fn reduction_offsets_into(subgroup_size: u32, offsets: &mut Vec<u32>) {
    offsets.clear();
    let mut width = subgroup_size.next_power_of_two() / 2;
    while width > 0 {
        offsets.push(width);
        width /= 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_enumerates_seven_ops() {
        assert_eq!(SubgroupOp::all().len(), 7);
    }
}
