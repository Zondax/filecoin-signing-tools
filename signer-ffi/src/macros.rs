#[cfg(feature = "with-jni")]
macro_rules! create_str {
    ($etc:expr, $e:expr) => {
        $etc.0
            .new_string($e)
            .expect("Couldn't create java string!")
            .into_inner()
    };
}
#[cfg(not(feature = "with-jni"))]
macro_rules! create_str {
    ($etc:expr, $e:expr) => {
        std::ffi::CString::new($e).unwrap().into_raw()
    };
}

#[cfg(feature = "with-jni")]
macro_rules! get_str {
    ($etc:expr, $e:expr) => {
        ffi_support::FfiStr::from_cstr(&$etc.0.get_string($e).expect("Couldn't get java string"))
            .as_str()
    };
}
#[cfg(not(feature = "with-jni"))]
macro_rules! get_str {
    ($etc:expr, $e:expr) => {
        $e.as_str()
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

#[cfg(feature = "with-jni")]
macro_rules! str_ret_ty {
    () => {
        jni::sys::jstring
    };
}
#[cfg(not(feature = "with-jni"))]
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
