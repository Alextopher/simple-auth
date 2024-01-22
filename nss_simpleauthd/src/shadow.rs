use authd::types::ToNSS;
use futures::executor::block_on;
use libnss::{
    interop::Response,
    shadow::{Shadow, ShadowHooks},
};
use tarpc::context;

use crate::{AuthdShadow, RPC};

impl ShadowHooks for AuthdShadow {
    fn get_all_entries() -> Response<Vec<Shadow>> {
        let mut cl = RPC.lock().unwrap();
        cl.with_client(
            |client| match block_on(client.get_all_shadow(context::current())) {
                Ok(passwds) => Response::Success(passwds.into_iter().map(|x| x.to_nss()).collect()),
                Err(_e) => Response::Unavail,
            },
        )
    }

    fn get_entry_by_name(name: String) -> libnss::interop::Response<libnss::shadow::Shadow> {
        let mut cl = RPC.lock().unwrap();
        cl.with_client(|client| {
            match block_on(client.get_shadow_by_name(context::current(), name)) {
                Ok(passwd) => match passwd {
                    Some(p) => Response::Success(p.to_nss()),
                    None => Response::NotFound,
                },
                Err(_e) => Response::Unavail,
            }
        })
    }
}
