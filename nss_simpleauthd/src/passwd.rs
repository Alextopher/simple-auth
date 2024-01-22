use authd::types::ToNSS;
use futures::executor::block_on;
use libnss::{
    interop::Response,
    passwd::{Passwd, PasswdHooks},
};
use tarpc::context;

use crate::{AuthdPasswd, RPC};

impl PasswdHooks for AuthdPasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        let mut cl = RPC.lock().unwrap();
        cl.with_client(
            |client| match block_on(client.get_all_passwd(context::current())) {
                Ok(passwds) => Response::Success(passwds.into_iter().map(|x| x.to_nss()).collect()),
                Err(_e) => Response::Unavail,
            },
        )
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        let mut cl = RPC.lock().unwrap();
        cl.with_client(
            |client| match block_on(client.get_passwd_by_uid(context::current(), uid)) {
                Ok(passwd) => match passwd {
                    Some(p) => Response::Success(p.to_nss()),
                    None => Response::NotFound,
                },
                Err(_e) => Response::Unavail,
            },
        )
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        let mut cl = RPC.lock().unwrap();
        cl.with_client(|client| {
            match block_on(client.get_passwd_by_name(context::current(), name)) {
                Ok(passwd) => match passwd {
                    Some(p) => Response::Success(p.to_nss()),
                    None => Response::NotFound,
                },
                Err(_e) => Response::Unavail,
            }
        })
    }
}
