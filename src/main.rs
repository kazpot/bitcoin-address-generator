#![feature(proc_macro_hygiene, decl_macro)]
#![feature(in_band_lifetimes)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
extern crate base64;

mod address;
mod auth;
mod crypto;
mod data;

use crate::address::seed::{encrypt_seed_with_password, gen_seed_with_password};
use crate::data::hd_wallet::HdWallet;
use address::address_gen::BtcAddress;
use auth::basic_auth::BasicAuth;
use data::multi_sig::MultiSig;
use env_logger;
use rocket::State;
use rocket_contrib::json::{Json, JsonValue};
use std::{env, process};

#[derive(Debug)]
struct WalletSeed {
    value: String,
}

#[get("/health")]
fn get_health() -> JsonValue {
    json!({"health": "ok"})
}

#[post("/hd-segwit-address", format = "json", data = "<input>")]
fn get_hd_segwit_address(
    _auth: BasicAuth,
    seed: State<WalletSeed>,
    input: Json<HdWallet>,
) -> JsonValue {
    log::info!("input: {:?}", input);

    let seed = &seed.value;
    if let Ok(segwit_address) =
        BtcAddress::gen_segwit_address_by_address_index(seed.as_bytes(), input.address_index)
    {
        return json!({"result": "success", "btc_segwit_address": segwit_address});
    }
    json!({"result": "failed"})
}

#[post("/multi-sig-address", format = "json", data = "<input>")]
fn get_multi_sig_address(_auth: BasicAuth, input: Json<MultiSig>) -> JsonValue {
    log::info!("input: {:?}", input);

    if input.m != input.public_keys.len() as u32 {
        return json!({"result": "failed", "detail": "m must match public key size!"});
    }

    if let Ok(multi_sig_address) =
        BtcAddress::gen_multi_sig_p2sh_address(input.n, &input.public_keys, true)
    {
        json!({"result": "success", "multi_sig_address": multi_sig_address})
    } else {
        json!({"result": "failed"})
    }
}

#[catch(400)]
fn bad_request() -> JsonValue {
    json!({"error": "Bad request!"})
}

#[catch(404)]
fn not_found() -> JsonValue {
    json!({"error": "Not found!"})
}

#[catch(401)]
fn unauthorized_user() -> JsonValue {
    json!({"error": "Unauthorized!"})
}

fn main() {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info")
    }
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() > 2 {
        println!("Invalid arguments");
        process::exit(1)
    }

    if args.len() == 2 {
        if args[1] == "seed" {
            let encrypted_seed = encrypt_seed_with_password();
            println!("encrypted seed: {}", encrypted_seed);
            process::exit(0)
        } else {
            println!("Invalid method argument");
            process::exit(1)
        }
    }

    let seed = gen_seed_with_password();
    let wallet_seed = WalletSeed { value: seed };
    log::debug!("wallet_seed: {:?}", wallet_seed);

    let _ = rocket::ignite()
        .manage(wallet_seed)
        .mount(
            "/",
            routes![get_health, get_hd_segwit_address, get_multi_sig_address],
        )
        .register(catchers![not_found, unauthorized_user, bad_request])
        .launch();
}
