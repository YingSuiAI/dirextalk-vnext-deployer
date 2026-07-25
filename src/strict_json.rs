//! Duplicate-key-detecting JSON decoding used at security-sensitive boundaries.
use std::collections::HashSet;

use serde::{
    Deserialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Deserializer, Map, Value};

use crate::{ReleaseError, Result};

pub fn parse_value(bytes: &[u8]) -> Result<Value> {
    let mut deserializer = Deserializer::from_slice(bytes);
    let value = DupValue::deserialize(&mut deserializer)?.0;
    deserializer.end().map_err(ReleaseError::from)?;
    Ok(value)
}

pub fn canonical_bytes(value: &Value, trailing_newline: bool) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)?;
    if trailing_newline {
        bytes.push(b'\n');
    }
    Ok(bytes)
}

struct DupValue(Value);

impl<'de> Deserialize<'de> for DupValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DupVisitor)
    }
}

struct DupVisitor;

impl<'de> Visitor<'de> for DupVisitor {
    type Value = DupValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(DupValue(Value::Bool(value)))
    }
    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(DupValue(Value::Number(value.into())))
    }
    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(DupValue(Value::Number(value.into())))
    }
    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(|number| DupValue(Value::Number(number)))
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }
    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(DupValue(Value::String(value.to_owned())))
    }
    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(DupValue(Value::String(value)))
    }
    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(DupValue(Value::Null))
    }
    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(DupValue(Value::Null))
    }
    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DupValue::deserialize(deserializer)
    }
    fn visit_seq<A>(self, mut access: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = access.next_element::<DupValue>()? {
            values.push(value.0);
        }
        Ok(DupValue(Value::Array(values)))
    }
    fn visit_map<A>(self, mut access: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let value = access.next_value::<DupValue>()?;
            map.insert(key, value.0);
        }
        Ok(DupValue(Value::Object(map)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicates_at_any_nesting_depth() {
        for bytes in [
            br#"{"a":1,"a":1}"#.as_slice(),
            br#"{"a":{"b":[{"c":1,"c":1}]}}"#.as_slice(),
        ] {
            assert!(parse_value(bytes).is_err());
        }
        assert!(parse_value(br#"{"a":{"b":[{"c":1}]}}"#).is_ok());
    }
}
