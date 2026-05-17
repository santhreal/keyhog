//! Tensor-network inspired contraction ordering for fusion planning.

/// Return a stable greedy contraction order.
///
/// Larger dimensions are contracted first to reduce large intermediate
/// buffers early; equal dimensions keep ascending index order.
#[must_use]
pub fn optimal_fusion_order(dimensions: &[u32]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..dimensions.len()).collect();
    order.sort_by(|&left, &right| {
        dimensions[right]
            .cmp(&dimensions[left])
            .then_with(|| left.cmp(&right))
    });
    order
}

/// Score a proposed contraction order with saturating arithmetic.
#[must_use]
pub fn fusion_order_cost(dimensions: &[u32], order: &[usize]) -> u64 {
    let mut running = 1u64;
    let mut cost = 0u64;
    for &index in order {
        let Some(dimension) = dimensions.get(index).copied() else {
            continue;
        };
        let dimension = u64::from(dimension).max(1);
        running = running.saturating_mul(dimension);
        cost = cost.saturating_add(running);
    }
    cost
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn largest_dimension_contracted_first() {
        let dims = [4, 16, 8, 2];
        let order = optimal_fusion_order(&dims);
        // Should be sorted by descending dimension: 16(1), 8(2), 4(0), 2(3).
        assert_eq!(order, vec![1, 2, 0, 3]);
    }

    #[test]
    fn equal_dimensions_preserve_index_order() {
        let dims = [4, 4, 4];
        let order = optimal_fusion_order(&dims);
        assert_eq!(order, vec![0, 1, 2]);
    }

    #[test]
    fn cost_is_positive() {
        let dims = [8, 4, 2];
        let order = optimal_fusion_order(&dims);
        let cost = fusion_order_cost(&dims, &order);
        assert!(cost > 0);
    }

    #[test]
    fn empty_dimensions() {
        let order = optimal_fusion_order(&[]);
        assert!(order.is_empty());
        assert_eq!(fusion_order_cost(&[], &[]), 0);
    }

    #[test]
    fn single_dimension() {
        let dims = [42];
        let order = optimal_fusion_order(&dims);
        assert_eq!(order, vec![0]);
        let cost = fusion_order_cost(&dims, &order);
        assert_eq!(cost, 42);
    }
}
