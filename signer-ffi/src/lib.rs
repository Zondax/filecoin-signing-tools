use ffi_support::{
    call_with_result, IntoFfi, define_box_destructor,ExternError, FfiStr, 
};
use filecoin_signer::{key_derive, PrivateKey, PublicKey, PublicKeyCompressed};
use std::{
    ffi::CString,
    os::raw::c_char,
};

#[repr(C)]
pub struct ExtendedKey {
    pub address: *mut c_char,
    pub private_key: PrivateKey,
    pub public_key_compressed: PublicKeyCompressed,
    pub public_key: PublicKey,
}

unsafe impl IntoFfi for ExtendedKey {
    type Value = *mut ExtendedKey;

    #[inline]
    fn ffi_default() -> Self::Value {
        std::ptr::null_mut()
    }

    #[inline]
    fn into_ffi_value(self) -> Self::Value {
        Box::into_raw(Box::new(self))
    }
}

impl From<filecoin_signer::ExtendedKey> for ExtendedKey {
    fn from(from: filecoin_signer::ExtendedKey) -> Self {
        Self {
            private_key: from.private_key,
            public_key: from.public_key,
            public_key_compressed: from.public_key_compressed,
            address: CString::new(from.address).unwrap().into_raw(),
        }
    }
}

#[no_mangle]
pub extern "C" fn filecoin_key_derive(
    mnemonic: FfiStr<'_>,
    path: FfiStr<'_>,
    error: &mut ExternError,
) -> *mut ExtendedKey {
    call_with_result(error, || -> Result<ExtendedKey, ExternError> {
        let a = key_derive(mnemonic.as_str(), path.as_str())?;
        Ok(a.into())
    })
}

define_box_destructor!(ExtendedKey, filecoin_key_derive_free);

#[cfg(test)]
mod tests {
    use ffi_support::{FfiStr, ExternError};
    use crate::{filecoin_key_derive, filecoin_key_derive_free};
    use std::ffi::CStr;

    #[test]
    fn key_derive() {
        let mut error = ExternError::default();
        let ptr = filecoin_key_derive(
            FfiStr::from_cstr(CStr::from_bytes_with_nul(b"a\0").unwrap()),
            FfiStr::from_cstr(CStr::from_bytes_with_nul(b"a\0").unwrap()),
            &mut error
        );
        unsafe { filecoin_key_derive_free(ptr) };
    }
}