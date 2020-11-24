use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    database_dir: String,
    data_dir: String,

    downstreams: Vec<Downstream>,
    upstreams: Vec<Upstream>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Downstream {
    protocol: String,
    addr: String,
    auth_type: String,
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Upstream {
    name: String,
    protocol: String,
    addr: String,
    auth_type: String,
    username: String,
    password: String,
}