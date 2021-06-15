use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};

/// Basic auth object
pub struct BasicAuth {
    /// username
    pub username: String,
    /// password
    pub password: String,
}

impl BasicAuth {
    /// Returns Option containing BasicAuth object
    ///
    /// # Arguments
    ///
    /// * `header` - Header string
    fn from_authorization_header(header: &str) -> Option<BasicAuth> {
        let split = header.split_whitespace().collect::<Vec<_>>();
        if split.len() != 2 {
            return None;
        }

        if split[0] != "Basic" {
            return None;
        }

        Self::from_base64_encoded(split[1])
    }

    /// Returns Option containing BasicAuth object after verifying username and password
    ///
    /// # Arguments
    ///
    /// * `base_64_string` - Base64 encoded string which is formatted like username:password
    fn from_base64_encoded(base64_string: &str) -> Option<BasicAuth> {
        let decoded = base64::decode(base64_string).ok()?;
        let decode_str = String::from_utf8(decoded).ok()?;
        let split = decode_str.split(":").collect::<Vec<_>>();

        if split.len() != 2 {
            return None;
        }

        let (username, password) = (split[0].to_string(), split[1].to_string());

        if username != "bitcoin" && password != "nakamotosatoshi" {
            return None;
        }

        Some(BasicAuth { username, password })
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for BasicAuth {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
        let auth_header = request.headers().get_one("Authorization");
        if let Some(auth_header) = auth_header {
            if let Some(auth) = Self::from_authorization_header(auth_header) {
                return Outcome::Success(auth);
            }
        }
        Outcome::Failure((Status::Unauthorized, ()))
    }
}
