use std::ffi::CStr;
use std::str;

use libc::c_int;
use libnss::{
    group::{CGroup, GroupHooks},
    interop::Response,
};

use crate::{ffi::GROUP_ITERATOR, AuthdGroup};

#[no_mangle]
extern "C" fn _nss_simpleauthd_setgrent() -> c_int {
    let mut iter = GROUP_ITERATOR.lock().unwrap();

    let status = match AuthdGroup::get_all_entries() {
        Response::Success(entries) => iter.open(entries),
        response => response.to_status(),
    };

    status as c_int
}

#[no_mangle]
extern "C" fn _nss_simpleauthd_endgrent() -> c_int {
    let mut iter = GROUP_ITERATOR.lock().unwrap();
    iter.close() as c_int
}

#[no_mangle]
unsafe extern "C" fn _nss_simpleauthd_getgrent_r(
    result: *mut CGroup,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int {
    let mut iter = GROUP_ITERATOR.lock().unwrap();
    iter.next().to_c(result, buf, buflen, errnop) as c_int
}

#[no_mangle]
unsafe extern "C" fn _nss_simpleauthd_getgrgid_r(
    uid: libc::uid_t,
    result: *mut CGroup,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int {
    AuthdGroup::get_entry_by_gid(uid).to_c(result, buf, buflen, errnop) as c_int
}

#[no_mangle]
unsafe extern "C" fn nss_simpleauthd_getgrnam_r(
    name_: *const libc::c_char,
    result: *mut CGroup,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int {
    let cstr = CStr::from_ptr(name_);

    let response = match str::from_utf8(cstr.to_bytes()) {
        Ok(name) => AuthdGroup::get_entry_by_name(name.to_string()),
        Err(_) => Response::NotFound,
    };

    response.to_c(result, buf, buflen, errnop) as c_int
}
