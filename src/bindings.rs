// Generated by `wit-bindgen` 0.25.0. DO NOT EDIT!
// Options used:
#[doc(hidden)]
#[allow(non_snake_case)]
pub unsafe fn _export_generatesecret_cabi<T: Guest>() -> *mut u8 {
    #[cfg(target_arch = "wasm32")]
    _rt::run_ctors_once();
    let result0 = T::generatesecret();
    let ptr1 = _RET_AREA.0.as_mut_ptr().cast::<u8>();
    match result0 {
        Ok(e) => {
            *ptr1.add(0).cast::<u8>() = (0i32) as u8;
            let vec2 = (e).into_boxed_slice();
            let ptr2 = vec2.as_ptr().cast::<u8>();
            let len2 = vec2.len();
            ::core::mem::forget(vec2);
            *ptr1.add(8).cast::<usize>() = len2;
            *ptr1.add(4).cast::<*mut u8>() = ptr2.cast_mut();
        }
        Err(e) => {
            *ptr1.add(0).cast::<u8>() = (1i32) as u8;
            let vec3 = (e.into_bytes()).into_boxed_slice();
            let ptr3 = vec3.as_ptr().cast::<u8>();
            let len3 = vec3.len();
            ::core::mem::forget(vec3);
            *ptr1.add(8).cast::<usize>() = len3;
            *ptr1.add(4).cast::<*mut u8>() = ptr3.cast_mut();
        }
    };
    ptr1
}
#[doc(hidden)]
#[allow(non_snake_case)]
pub unsafe fn __post_return_generatesecret<T: Guest>(arg0: *mut u8) {
    let l0 = i32::from(*arg0.add(0).cast::<u8>());
    match l0 {
        0 => {
            let l1 = *arg0.add(4).cast::<*mut u8>();
            let l2 = *arg0.add(8).cast::<usize>();
            let base3 = l1;
            let len3 = l2;
            _rt::cabi_dealloc(base3, len3 * 1, 1);
        }
        _ => {
            let l4 = *arg0.add(4).cast::<*mut u8>();
            let l5 = *arg0.add(8).cast::<usize>();
            _rt::cabi_dealloc(l4, l5, 1);
        }
    }
}
#[doc(hidden)]
#[allow(non_snake_case)]
pub unsafe fn _export_combinesecret_cabi<T: Guest>(arg0: *mut u8, arg1: usize) -> *mut u8 {
    #[cfg(target_arch = "wasm32")]
    _rt::run_ctors_once();
    let len0 = arg1;
    let result1 = T::combinesecret(_rt::Vec::from_raw_parts(arg0.cast(), len0, len0));
    let ptr2 = _RET_AREA.0.as_mut_ptr().cast::<u8>();
    match result1 {
        Ok(e) => {
            *ptr2.add(0).cast::<u8>() = (0i32) as u8;
            let vec3 = (e).into_boxed_slice();
            let ptr3 = vec3.as_ptr().cast::<u8>();
            let len3 = vec3.len();
            ::core::mem::forget(vec3);
            *ptr2.add(8).cast::<usize>() = len3;
            *ptr2.add(4).cast::<*mut u8>() = ptr3.cast_mut();
        }
        Err(e) => {
            *ptr2.add(0).cast::<u8>() = (1i32) as u8;
            let vec4 = (e.into_bytes()).into_boxed_slice();
            let ptr4 = vec4.as_ptr().cast::<u8>();
            let len4 = vec4.len();
            ::core::mem::forget(vec4);
            *ptr2.add(8).cast::<usize>() = len4;
            *ptr2.add(4).cast::<*mut u8>() = ptr4.cast_mut();
        }
    };
    ptr2
}
#[doc(hidden)]
#[allow(non_snake_case)]
pub unsafe fn __post_return_combinesecret<T: Guest>(arg0: *mut u8) {
    let l0 = i32::from(*arg0.add(0).cast::<u8>());
    match l0 {
        0 => {
            let l1 = *arg0.add(4).cast::<*mut u8>();
            let l2 = *arg0.add(8).cast::<usize>();
            let base3 = l1;
            let len3 = l2;
            _rt::cabi_dealloc(base3, len3 * 1, 1);
        }
        _ => {
            let l4 = *arg0.add(4).cast::<*mut u8>();
            let l5 = *arg0.add(8).cast::<usize>();
            _rt::cabi_dealloc(l4, l5, 1);
        }
    }
}
#[doc(hidden)]
#[allow(non_snake_case)]
pub unsafe fn _export_splitsecret_cabi<T: Guest>(arg0: *mut u8, arg1: usize) -> *mut u8 {
    #[cfg(target_arch = "wasm32")]
    _rt::run_ctors_once();
    let len0 = arg1;
    let result1 = T::splitsecret(_rt::Vec::from_raw_parts(arg0.cast(), len0, len0));
    let ptr2 = _RET_AREA.0.as_mut_ptr().cast::<u8>();
    match result1 {
        Ok(e) => {
            *ptr2.add(0).cast::<u8>() = (0i32) as u8;
            let vec3 = (e).into_boxed_slice();
            let ptr3 = vec3.as_ptr().cast::<u8>();
            let len3 = vec3.len();
            ::core::mem::forget(vec3);
            *ptr2.add(8).cast::<usize>() = len3;
            *ptr2.add(4).cast::<*mut u8>() = ptr3.cast_mut();
        }
        Err(e) => {
            *ptr2.add(0).cast::<u8>() = (1i32) as u8;
            let vec4 = (e.into_bytes()).into_boxed_slice();
            let ptr4 = vec4.as_ptr().cast::<u8>();
            let len4 = vec4.len();
            ::core::mem::forget(vec4);
            *ptr2.add(8).cast::<usize>() = len4;
            *ptr2.add(4).cast::<*mut u8>() = ptr4.cast_mut();
        }
    };
    ptr2
}
#[doc(hidden)]
#[allow(non_snake_case)]
pub unsafe fn __post_return_splitsecret<T: Guest>(arg0: *mut u8) {
    let l0 = i32::from(*arg0.add(0).cast::<u8>());
    match l0 {
        0 => {
            let l1 = *arg0.add(4).cast::<*mut u8>();
            let l2 = *arg0.add(8).cast::<usize>();
            let base3 = l1;
            let len3 = l2;
            _rt::cabi_dealloc(base3, len3 * 1, 1);
        }
        _ => {
            let l4 = *arg0.add(4).cast::<*mut u8>();
            let l5 = *arg0.add(8).cast::<usize>();
            _rt::cabi_dealloc(l4, l5, 1);
        }
    }
}
#[doc(hidden)]
#[allow(non_snake_case)]
pub unsafe fn _export_verifysecret_cabi<T: Guest>(
    arg0: *mut u8,
    arg1: usize,
    arg2: *mut u8,
    arg3: usize,
) -> *mut u8 {
    #[cfg(target_arch = "wasm32")]
    _rt::run_ctors_once();
    let len0 = arg1;
    let len1 = arg3;
    let result2 = T::verifysecret(
        _rt::Vec::from_raw_parts(arg0.cast(), len0, len0),
        _rt::Vec::from_raw_parts(arg2.cast(), len1, len1),
    );
    let ptr3 = _RET_AREA.0.as_mut_ptr().cast::<u8>();
    match result2 {
        Ok(e) => {
            *ptr3.add(0).cast::<u8>() = (0i32) as u8;
            *ptr3.add(4).cast::<u8>() = (match e {
                true => 1,
                false => 0,
            }) as u8;
        }
        Err(e) => {
            *ptr3.add(0).cast::<u8>() = (1i32) as u8;
            let vec4 = (e.into_bytes()).into_boxed_slice();
            let ptr4 = vec4.as_ptr().cast::<u8>();
            let len4 = vec4.len();
            ::core::mem::forget(vec4);
            *ptr3.add(8).cast::<usize>() = len4;
            *ptr3.add(4).cast::<*mut u8>() = ptr4.cast_mut();
        }
    };
    ptr3
}
#[doc(hidden)]
#[allow(non_snake_case)]
pub unsafe fn __post_return_verifysecret<T: Guest>(arg0: *mut u8) {
    let l0 = i32::from(*arg0.add(0).cast::<u8>());
    match l0 {
        0 => (),
        _ => {
            let l1 = *arg0.add(4).cast::<*mut u8>();
            let l2 = *arg0.add(8).cast::<usize>();
            _rt::cabi_dealloc(l1, l2, 1);
        }
    }
}
pub trait Guest {
    fn generatesecret() -> Result<_rt::Vec<u8>, _rt::String>;
    fn combinesecret(sharebytes: _rt::Vec<u8>) -> Result<_rt::Vec<u8>, _rt::String>;
    fn splitsecret(secret: _rt::Vec<u8>) -> Result<_rt::Vec<u8>, _rt::String>;
    fn verifysecret(
        sharebytes: _rt::Vec<u8>,
        verifybytes: _rt::Vec<u8>,
    ) -> Result<bool, _rt::String>;
}
#[doc(hidden)]

macro_rules! __export_world_vsssworld_cabi{
  ($ty:ident with_types_in $($path_to_types:tt)*) => (const _: () = {

    #[export_name = "generatesecret"]
    unsafe extern "C" fn export_generatesecret() -> *mut u8 {
      $($path_to_types)*::_export_generatesecret_cabi::<$ty>()
    }
    #[export_name = "cabi_post_generatesecret"]
    unsafe extern "C" fn _post_return_generatesecret(arg0: *mut u8,) {
      $($path_to_types)*::__post_return_generatesecret::<$ty>(arg0)
    }
    #[export_name = "combinesecret"]
    unsafe extern "C" fn export_combinesecret(arg0: *mut u8,arg1: usize,) -> *mut u8 {
      $($path_to_types)*::_export_combinesecret_cabi::<$ty>(arg0, arg1)
    }
    #[export_name = "cabi_post_combinesecret"]
    unsafe extern "C" fn _post_return_combinesecret(arg0: *mut u8,) {
      $($path_to_types)*::__post_return_combinesecret::<$ty>(arg0)
    }
    #[export_name = "splitsecret"]
    unsafe extern "C" fn export_splitsecret(arg0: *mut u8,arg1: usize,) -> *mut u8 {
      $($path_to_types)*::_export_splitsecret_cabi::<$ty>(arg0, arg1)
    }
    #[export_name = "cabi_post_splitsecret"]
    unsafe extern "C" fn _post_return_splitsecret(arg0: *mut u8,) {
      $($path_to_types)*::__post_return_splitsecret::<$ty>(arg0)
    }
    #[export_name = "verifysecret"]
    unsafe extern "C" fn export_verifysecret(arg0: *mut u8,arg1: usize,arg2: *mut u8,arg3: usize,) -> *mut u8 {
      $($path_to_types)*::_export_verifysecret_cabi::<$ty>(arg0, arg1, arg2, arg3)
    }
    #[export_name = "cabi_post_verifysecret"]
    unsafe extern "C" fn _post_return_verifysecret(arg0: *mut u8,) {
      $($path_to_types)*::__post_return_verifysecret::<$ty>(arg0)
    }
  };);
}
#[doc(hidden)]
pub(crate) use __export_world_vsssworld_cabi;
#[repr(align(4))]
struct _RetArea([::core::mem::MaybeUninit<u8>; 12]);
static mut _RET_AREA: _RetArea = _RetArea([::core::mem::MaybeUninit::uninit(); 12]);
mod _rt {

    #[cfg(target_arch = "wasm32")]
    pub fn run_ctors_once() {
        wit_bindgen_rt::run_ctors_once();
    }
    pub unsafe fn cabi_dealloc(ptr: *mut u8, size: usize, align: usize) {
        if size == 0 {
            return;
        }
        let layout = alloc::Layout::from_size_align_unchecked(size, align);
        alloc::dealloc(ptr as *mut u8, layout);
    }
    pub use alloc_crate::alloc;
    pub use alloc_crate::string::String;
    pub use alloc_crate::vec::Vec;
    extern crate alloc as alloc_crate;
}

/// Generates `#[no_mangle]` functions to export the specified type as the
/// root implementation of all generated traits.
///
/// For more information see the documentation of `wit_bindgen::generate!`.
///
/// ```rust
/// # macro_rules! export{ ($($t:tt)*) => (); }
/// # trait Guest {}
/// struct MyType;
///
/// impl Guest for MyType {
///     // ...
/// }
///
/// export!(MyType);
/// ```
#[allow(unused_macros)]
#[doc(hidden)]

macro_rules! __export_vsssworld_impl {
  ($ty:ident) => (self::export!($ty with_types_in self););
  ($ty:ident with_types_in $($path_to_types_root:tt)*) => (
  $($path_to_types_root)*::__export_world_vsssworld_cabi!($ty with_types_in $($path_to_types_root)*);
  )
}
#[doc(inline)]
pub(crate) use __export_vsssworld_impl as export;

#[cfg(target_arch = "wasm32")]
#[link_section = "component-type:wit-bindgen:0.25.0:vsssworld:encoded world"]
#[doc(hidden)]
pub static __WIT_BINDGEN_COMPONENT_TYPE: [u8; 323] = *b"\
\0asm\x0d\0\x01\0\0\x19\x16wit-component-encoding\x04\0\x07\xc3\x01\x01A\x02\x01\
A\x0b\x01p}\x01j\x01\0\x01s\x01@\0\0\x01\x04\0\x0egeneratesecret\x01\x02\x01@\x01\
\x0asharebytes\0\0\x01\x04\0\x0dcombinesecret\x01\x03\x01@\x01\x06secret\0\0\x01\
\x04\0\x0bsplitsecret\x01\x04\x01j\x01\x7f\x01s\x01@\x02\x0asharebytes\0\x0bveri\
fybytes\0\0\x05\x04\0\x0cverifysecret\x01\x06\x04\x01\"component:vsss-component/\
vsssworld\x04\0\x0b\x0f\x01\0\x09vsssworld\x03\0\0\0G\x09producers\x01\x0cproces\
sed-by\x02\x0dwit-component\x070.208.1\x10wit-bindgen-rust\x060.25.0";

#[inline(never)]
#[doc(hidden)]
#[cfg(target_arch = "wasm32")]
pub fn __link_custom_section_describing_imports() {
    wit_bindgen_rt::maybe_link_cabi_realloc();
}