use std::ffi::CStr;
use std::str;

use libc::c_int;
use libnss::{
    interop::Response,
    shadow::{CShadow, ShadowHooks},
};

use crate::{ffi::SHADOW_ITERATOR, AuthdShadow};

#[no_mangle]
extern "C" fn _nss_simpleauthd_setspent() -> c_int {
    let mut iter = SHADOW_ITERATOR.lock().unwrap();

    let status = match AuthdShadow::get_all_entries() {
        Response::Success(entries) => iter.open(entries),
        response => response.to_status(),
    };

    status as c_int
}

#[no_mangle]
extern "C" fn _nss_simpleauthd_endspent() -> c_int {
    let mut iter = SHADOW_ITERATOR.lock().unwrap();
    iter.close() as c_int
}

#[no_mangle]
unsafe extern "C" fn _nss_simpleauthd_getspent_r(
    result: *mut CShadow,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int {
    let mut iter = SHADOW_ITERATOR.lock().unwrap();
    iter.next().to_c(result, buf, buflen, errnop) as c_int
}

#[no_mangle]
unsafe extern "C" fn nss_simpleauthd_getspnam_r(
    name_: *const libc::c_char,
    result: *mut CShadow,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int {
    let cstr = CStr::from_ptr(name_);

    let response = match str::from_utf8(cstr.to_bytes()) {
        Ok(name) => AuthdShadow::get_entry_by_name(name.to_string()),
        Err(_) => Response::NotFound,
    };

    response.to_c(result, buf, buflen, errnop) as c_int
}
