// Errors start at 0x80 to avoid conflict with `filecoin_signer::error::Error`.

#[cfg(feature = "with-jni")]
macro_rules! create_string {
    ($etc:expr, $e:expr) => {
        $etc.0
            .new_string($e)
            .map(|rslt| rslt.into_inner() as *mut _)
            .map_err(|_| {
                let code = ffi_support::ErrorCode::new(0x80);
                ffi_support::ExternError::new_error(code, "Couldn't create JAVA string")
            })
    };
}
#[cfg(not(feature = "with-jni"))]
macro_rules! create_string {
    ($etc:expr, $e:expr) => {
        std::ffi::CString::new($e)
            .map(|rslt| rslt.into_raw())
            .map_err(|_| {
                let code = ffi_support::ErrorCode::new(0x81);
                ffi_support::ExternError::new_error(code, "Couldn't create string")
            })
    };
}

#[cfg(feature = "with-jni")]
macro_rules! get_string {
    ($etc:expr, $e:expr) => {
        $etc.0.get_string($e).map_err(|_| {
            let code = ffi_support::ErrorCode::new(0x82);
            ffi_support::ExternError::new_error(code, "Couldn't retrieve JAVA string")
        })
    };
}
#[cfg(not(feature = "with-jni"))]
macro_rules! get_string {
    ($etc:expr, $e:expr) => {
        Ok::<_, ffi_support::ExternError>($e)
    };
}

#[cfg(feature = "with-jni")]
macro_rules! ptr {
    ($ty:ty) => {
        jni::sys::jlong
    };
}
#[cfg(not(feature = "with-jni"))]
macro_rules! ptr { ($ty:ty) => { *mut $ty } }

#[cfg(feature = "with-jni")]
macro_rules! str_arg_ty {
    () => {
        jni::objects::JString
    };
}
#[cfg(not(feature = "with-jni"))]
macro_rules! str_arg_ty { () => { ffi_support::FfiStr<'_> } }

macro_rules! str_ret_ty { () => { *mut std::os::raw::c_char } }

macro_rules! create_fn {
    ($fn_ffi_name:ident|$fn_jni_name:ident: ($($arg_name:ident: $arg_ty:ty),*) -> $rslt:ty, |$etc:pat| $fn_block:block) => {
        #[cfg(feature = "with-jni")]
        #[no_mangle]
        pub extern "system" fn $fn_jni_name(
            env: jni::JNIEnv,
            class: jni::objects::JClass,
            $($arg_name: $arg_ty),*
        ) -> $rslt {
            #[allow(unused_mut)]
            let mut closure = move |$etc: (jni::JNIEnv<'_>, jni::objects::JClass<'_>)| $fn_block;
            closure((env, class)) as $rslt
        }

        #[cfg(not(feature = "with-jni"))]
        #[no_mangle]
        pub extern "C" fn $fn_ffi_name($($arg_name: $arg_ty),*) -> $rslt {
            #[allow(unused_mut)]
            let mut closure = move |_: ()| $fn_block;
            closure(()) as $rslt
        }
    }
}

macro_rules! create_fn_destructor {
    ($struct:ty, $fn_ffi_name:ident|$fn_jni_name:ident) => {
        create_fn!($fn_ffi_name|$fn_jni_name: (ptr: *mut $struct) -> (), |_| {
            ffi_support::abort_on_panic::with_abort_on_panic(|| {
                if  !ptr.is_null() {
                    let _box = unsafe { Box::from_raw(ptr) };
                }
            });
        });
    }
}
