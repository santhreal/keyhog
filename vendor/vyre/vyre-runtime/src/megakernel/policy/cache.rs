use super::{MegakernelLaunchPolicy, MegakernelLaunchRecommendation, MegakernelLaunchRequest};
use rustc_hash::FxHashMap;
use std::cell::RefCell;
use std::collections::VecDeque;

const LAUNCH_RECOMMENDATION_CACHE_CAP: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct LaunchRecommendationCacheKey {
    pub(super) policy: MegakernelLaunchPolicy,
    pub(super) request: MegakernelLaunchRequest,
}

#[derive(Default)]
pub(super) struct LaunchRecommendationCache {
    pub(super) entries: FxHashMap<LaunchRecommendationCacheKey, MegakernelLaunchRecommendation>,
    pub(super) order: VecDeque<LaunchRecommendationCacheKey>,
}

impl LaunchRecommendationCache {
    pub(super) fn get(
        &self,
        key: &LaunchRecommendationCacheKey,
    ) -> Option<MegakernelLaunchRecommendation> {
        self.entries.get(key).copied()
    }

    pub(super) fn insert(
        &mut self,
        key: LaunchRecommendationCacheKey,
        value: MegakernelLaunchRecommendation,
    ) {
        let is_new = self.entries.insert(key, value).is_none();
        if !is_new {
            return;
        }
        self.order.push_back(key);
        while self.entries.len() > LAUNCH_RECOMMENDATION_CACHE_CAP {
            let Some(evicted) = self.order.pop_front() else {
                break;
            };
            if self.entries.remove(&evicted).is_some() {
                continue;
            }
        }
        while self.order.len() > self.entries.len() {
            let Some(front) = self.order.pop_front() else {
                break;
            };
            if self.entries.contains_key(&front) {
                self.order.push_front(front);
                break;
            }
        }
    }
}

thread_local! {
    pub(super) static LAUNCH_RECOMMENDATION_CACHE: RefCell<LaunchRecommendationCache> =
        RefCell::new(LaunchRecommendationCache::default());
}
