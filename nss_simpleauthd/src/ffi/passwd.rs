use libc::c_int;
use libnss::interop::Response;
use libnss::passwd::{CPasswd, PasswdHooks};

use std::ffi::CStr;
use std::str;

use crate::ffi::PASSWD_ITERATOR;
use crate::AuthdPasswd;

#[no_mangle]
extern "C" fn _nss_simpleauthd_setpwent() -> c_int {
    let mut iter = PASSWD_ITERATOR.lock().unwrap();

    let status = match AuthdPasswd::get_all_entries() {
        Response::Success(entries) => iter.open(entries),
        response => response.to_status(),
    };

    status as c_int
}

#[no_mangle]
extern "C" fn _nss_simpleauthd_endpwent() -> c_int {
    let mut iter = PASSWD_ITERATOR.lock().unwrap();
    iter.close() as c_int
}

#[no_mangle]
unsafe extern "C" fn _nss_simpleauthd_getpwent_r(
    result: *mut CPasswd,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int {
    let mut iter = PASSWD_ITERATOR.lock().unwrap();
    iter.next().to_c(result, buf, buflen, errnop) as c_int
}

#[no_mangle]
unsafe extern "C" fn _nss_simpleauthd_getpwuid_r(
    uid: libc::uid_t,
    result: *mut CPasswd,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int {
    AuthdPasswd::get_entry_by_uid(uid).to_c(result, buf, buflen, errnop) as c_int
}

#[no_mangle]
unsafe extern "C" fn nss_simpleauthd_getpwnam_r(
    name_: *const libc::c_char,
    result: *mut CPasswd,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int {
    let cstr = CStr::from_ptr(name_);

    let response = match str::from_utf8(cstr.to_bytes()) {
        Ok(name) => AuthdPasswd::get_entry_by_name(name.to_string()),
        Err(_) => Response::NotFound,
    };

    response.to_c(result, buf, buflen, errnop) as c_int
}
