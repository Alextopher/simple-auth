lazy_static::lazy_static! {
    pub static ref CFG: NssConfig = {
        let mut cfg: NssConfig =  toml::from_slice(std::fs::read(authd::find_config_dir().map(|cd| cd.join("nss_simpleauthd.toml")).expect("no nss_simpleauthd.toml found!")).unwrap().as_slice()).unwrap();
        cfg.cert = shellexpand::full(&cfg.cert).unwrap().to_string();
        cfg
    };
}

#[derive(serde::Deserialize)]
pub struct NssConfig {
    pub host: authd::SocketName,
    pub cert: String,
}
