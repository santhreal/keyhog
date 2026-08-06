use std::collections::{BTreeMap, BTreeSet};

/// Keywords shorter than this are value prefixes or separators, not service names.
pub(crate) const MIN_SERVICE_KEYWORD_LEN: usize = 4;
/// A keyword spanning this many detector-id stems is a generic role word.
pub(crate) const GENERIC_STEM_SPREAD_LIMIT: usize = 3;

pub(crate) struct ServiceVocabularyDetector<'a> {
    pub(crate) id: &'a str,
    pub(crate) generic_family: bool,
    pub(crate) keywords: &'a [String],
}

fn detector_id_stem(detector_id: &str) -> &str {
    detector_id
        .split('-')
        .next()
        .map_or(detector_id, |stem| stem)
}

pub(crate) fn build_service_vocabulary<'a>(
    detectors: impl IntoIterator<Item = ServiceVocabularyDetector<'a>>,
) -> Vec<String> {
    let mut generic_words = BTreeSet::new();
    let mut stems_by_keyword: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for detector in detectors {
        if detector.generic_family {
            generic_words.extend(
                detector
                    .keywords
                    .iter()
                    .map(|keyword| keyword.to_ascii_lowercase()),
            );
            continue;
        }
        let stem = detector_id_stem(detector.id);
        for keyword in detector.keywords {
            stems_by_keyword
                .entry(keyword.to_ascii_lowercase())
                .or_default()
                .insert(stem.to_owned());
        }
    }

    stems_by_keyword
        .into_iter()
        .filter(|(keyword, stems)| {
            keyword.len() >= MIN_SERVICE_KEYWORD_LEN
                && stems.len() < GENERIC_STEM_SPREAD_LIMIT
                && !generic_words
                    .iter()
                    .any(|generic| generic.contains(keyword.as_str()))
        })
        .map(|(keyword, _)| keyword)
        .collect()
}
