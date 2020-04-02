#[cfg(feature = "with-jni")]
macro_rules! ptr {
    ($ty:ty) => { jni::sys::jlong }
}
#[cfg(not(feature = "with-jni"))]
macro_rules! ptr {
    ($ty:ty) => { *mut $ty }
}

macro_rules! create_fn {
    ($fn_ffi_name:ident|$fn_jni_name:ident: ($($arg_name:ident: $arg_ty:ty),*) -> $rslt:ty $fn_block:block) => {
        #[cfg(feature = "with-jni")]
        #[no_mangle]
        pub extern "system" fn $fn_jni_name(
            _: jni::JNIEnv,
            _: jni::objects::JClass,
            $($arg_name: $arg_ty),*
        ) -> $rslt {
            ($fn_block) as $rslt
        }

        #[cfg(not(feature = "with-jni"))]
        #[no_mangle]
        pub extern "C" fn $fn_ffi_name($($arg_name: $arg_ty),*) -> $rslt {
            ($fn_block) as $rslt
        }
    }
}

macro_rules! create_fn_destructor {
    ($struct:ty, $fn_ffi_name:ident|$fn_jni_name:ident) => {
        create_fn!($fn_ffi_name|$fn_jni_name: (ptr: ptr!($struct)) -> () {
            ffi_support::abort_on_panic::with_abort_on_panic(|| {
                let p = (ptr) as *mut $struct;
                if  !p.is_null() {
                    unsafe { drop(Box::from_raw(p)) }
                }
            });
        });
    }
}