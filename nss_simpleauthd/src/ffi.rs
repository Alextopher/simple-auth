use std::sync::Mutex;

use libnss::group::Group;
use libnss::interop::Iterator;
use libnss::passwd::Passwd;
use libnss::shadow::Shadow;

// Required by nss bindings
lazy_static::lazy_static! {
    static ref PASSWD_ITERATOR: Mutex<Iterator<Passwd>> = Mutex::new(Iterator::<Passwd>::new());
    static ref GROUP_ITERATOR: Mutex<Iterator<Group>> = Mutex::new(Iterator::<Group>::new());
    static ref SHADOW_ITERATOR: Mutex<Iterator<Shadow>> = Mutex::new(Iterator::<Shadow>::new());
}

mod group;
mod passwd;
mod shadow;
