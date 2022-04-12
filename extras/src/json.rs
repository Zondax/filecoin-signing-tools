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
    use cid::Cid;
    use serde::{de, Deserialize, Deserializer, Serializer};
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
    use base64::{decode, encode};
    use fvm_ipld_encoding::RawBytes;
    use serde::{de, Deserialize, Deserializer, Serializer};

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

pub mod vec_address {
    use fvm_shared::address::Address;
    use serde::{de, Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn serialize<S>(addresses: &Vec<Address>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut result = vec![];

        for a in addresses {
            let a: &Address = a;
            let s = a.to_string();
            result.push(s);
        }

        serializer.collect_seq(result)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Address>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let a: Vec<String> = Vec::deserialize(deserializer)?;
        let mut result: Vec<Address> = Vec::new();

        for s in a {
            let s: String = s;
            let address = Address::from_str(&s).map_err(de::Error::custom)?;
            result.push(address);
        }

        Ok(result)
    }
}

pub mod tokenamount {
    use fvm_shared::econ::TokenAmount;
    use serde::{de, Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn serialize<S>(token_amount: &TokenAmount, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = token_amount.to_string();
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<TokenAmount, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        TokenAmount::from_str(&s).map_err(de::Error::custom)
    }
}

pub mod serde_base64_vector {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(v: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(v))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        base64::decode(s).map_err(serde::de::Error::custom)
    }
}