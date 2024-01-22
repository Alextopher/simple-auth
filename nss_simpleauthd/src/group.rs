use authd::types::ToNSS;
use futures::executor::block_on;
use libnss::{
    group::{Group, GroupHooks},
    interop::Response,
};
use tarpc::context;

use crate::{AuthdGroup, RPC};

impl GroupHooks for AuthdGroup {
    fn get_all_entries() -> Response<Vec<Group>> {
        let mut cl = RPC.lock().unwrap();
        cl.with_client(
            |client| match block_on(client.get_all_groups(context::current())) {
                Ok(passwds) => Response::Success(passwds.into_iter().map(|x| x.to_nss()).collect()),
                Err(_e) => Response::Unavail,
            },
        )
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> libnss::interop::Response<libnss::group::Group> {
        let mut cl = RPC.lock().unwrap();
        cl.with_client(
            |client| match block_on(client.get_group_by_gid(context::current(), gid)) {
                Ok(passwd) => match passwd {
                    Some(p) => Response::Success(p.to_nss()),
                    None => Response::NotFound,
                },
                Err(_e) => Response::Unavail,
            },
        )
    }

    fn get_entry_by_name(name: String) -> libnss::interop::Response<libnss::group::Group> {
        let mut cl = RPC.lock().unwrap();
        cl.with_client(|client| {
            match block_on(client.get_group_by_name(context::current(), name)) {
                Ok(passwd) => match passwd {
                    Some(p) => Response::Success(p.to_nss()),
                    None => Response::NotFound,
                },
                Err(_e) => Response::Unavail,
            }
        })
    }
}
