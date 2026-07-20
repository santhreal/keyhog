use keyhog_core::SourceError;
use quick_xml::de::{Deserializer, PredefinedEntityResolver};
use quick_xml::events::Event;
use quick_xml::Reader;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ListBucketResult {
    #[serde(default)]
    pub(crate) contents: Vec<ListObject>,
    #[serde(default)]
    pub(crate) is_truncated: bool,
    #[serde(default)]
    pub(crate) next_continuation_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ListObject {
    pub(crate) key: String,
    /// None when the listing omitted Size (KH-1321); never collapse missing to 0.
    #[serde(default)]
    pub(crate) size: Option<u64>,
}

pub(crate) fn parse_s3_listing(body: &str) -> Result<ListBucketResult, SourceError> {
    if crate::cloud::contains_forbidden_xml_markup(body) {
        return Err(SourceError::Other(
            "S3 XML response contains unsupported DTD/entity declarations".into(),
        ));
    }

    let mut reader = Reader::from_str(body);
    loop {
        match reader.read_event() {
            Ok(Event::DocType(_)) => {
                return Err(SourceError::Other(
                    "S3 XML response contains unsupported DOCTYPE declarations".into(),
                ));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(err) => {
                return Err(SourceError::Other(format!(
                    "failed to validate S3 ListObjectsV2 XML: {err}"
                )));
            }
        }
    }

    let mut deserializer = Deserializer::from_str_with_resolver(body, PredefinedEntityResolver);
    ListBucketResult::deserialize(&mut deserializer)
        .map_err(|e| SourceError::Other(format!("failed to parse S3 ListObjectsV2 XML: {e}")))
}
