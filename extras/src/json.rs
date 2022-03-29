pub mod address {
    use fvm_shared::address::Address;
    use serde::{de, Deserialize, Deserializer, Serializer};
    use std::str::FromStr;
    
    pub fn serialize<S>(address: &Address, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = address.to_string();
        serializer.serialize_str(&s)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Address, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Address::from_str(&s).map_err(de::Error::custom)
    }    
}

pub mod cid {
    use serde::{de, Deserialize, Deserializer, Serializer};
    use cid::Cid;
    use std::str::FromStr;
    
    pub fn serialize<S>(cid: &Cid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = cid.to_string();
        serializer.serialize_str(&s)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Cid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Cid::from_str(&s).map_err(de::Error::custom)
    }    
}

pub mod rawbytes {
    use serde::{de, Deserialize, Deserializer, Serializer};
    use fvm_shared::encoding::RawBytes;
    use base64::{encode, decode};

    pub fn serialize<S>(raw: &RawBytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = encode(raw.bytes());
        serializer.serialize_str(&s)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<RawBytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let raw = decode(s).map_err(de::Error::custom)?;
        Ok(RawBytes::new(raw))
    }    
}