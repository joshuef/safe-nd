// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![allow(unsafe_code)]

//! App authentication token generation

use crate::errors::{Error, Result as NdResult};
use crate::IpcError;
use crate::{PublicKey, SafeKey, Signature};
use bincode::serialize;
use ffi_utils::ReprC;

use serde::{Deserialize, Serialize};

pub type CaveatName = String;
pub type CaveatContents = String;

/// Caveat to be optionally validate as a condition on the token
pub type Caveat = (CaveatName, CaveatContents);

/// Authentication Token, to be passed as means of authorisation to an app.
// To have signature of contents checked against the PublicKey in the account as validation.
#[repr(C)]
#[derive(Debug, Clone, Hash, Serialize, Deserialize, Ord, PartialEq, PartialOrd, Eq)]
pub struct AuthToken {
    /// Auth token version
    pub version: usize,
    /// Caveats for verifying for token to be considered valid.
    pub caveats: Vec<Caveat>,
    /// Signature of the serialized token for validation against tampering.
    pub signature: Option<Signature>,
}

impl Default for AuthToken {
    fn default() -> AuthToken {
        AuthToken {
            version: AuthToken::VERSION,
            caveats: Vec::new(),
            signature: None,
        }
    }
}

impl AuthToken {
    /// Token Struct Version
    pub const VERSION: usize = 1;

    /// Insantiate new token
    pub fn new() -> NdResult<AuthToken> {
        Ok(AuthToken::default())
    }
    /// Add a caveat to the token. This will update the token's signature.
    pub fn add_caveat(&mut self, caveat: Caveat, client_keys: &SafeKey) -> NdResult<()> {
        self.caveats.push(caveat);
        self.sign(&client_keys)?;

        Ok(())
    }
    /// Sign the token
    fn sign(&mut self, client_keys: &SafeKey) -> NdResult<()> {
        let serialized_caveats =
            serialize(&self.caveats).map_err(|e| format!("Error serializing caveats: {}", e))?;

        self.signature = Some(client_keys.sign(&serialized_caveats));

        Ok(())
    }

    /// Check if the token signature is valid for a given public key
    pub fn is_valid_for_public_key(&self, public_key: &PublicKey) -> NdResult<bool> {
        let serialised_caveats =
            serialize(&self.caveats).map_err(|e| Error::InvalidCaveats(e.to_string()))?;

        let sig = &self.signature.clone().unwrap();

        match public_key.verify(&sig, &serialised_caveats) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn get_caveat_by_name(&self, target_caveat: &str) -> Option<&Caveat> {
        self.caveats
            .iter()
            .find(|(caveat_name, _caveat_contents)| caveat_name == target_caveat)
    }

    /// Pass a function to check against the token. If a caveat to be checked doesn't exist,
    /// verification fails and 'false' is returned.
    pub fn verify_caveat(
        &self,
        caveat: &str,
        checker: fn(CaveatContents) -> bool,
    ) -> NdResult<bool> {
        // Check caveat w/ name exists....
        let (_caveat_name, caveat_contents) = match &self.get_caveat_by_name(caveat) {
            Some(target_caveat) => target_caveat,
            None => return Ok(false), // Or should we error here?
        };

        // run against supplied checker...
        let validity = checker(caveat_contents.clone());
        Ok(validity)
    }

    /// Constructs FFI wrapper for the native Rust object, consuming self.
    pub fn into_repr_c(self) -> Result<AuthToken, String> {
        let Self {
            caveats,
            version,
            signature,
        } = self;

        Ok(AuthToken {
            caveats,
            version,
            signature,
        })
    }
}

impl ReprC for AuthToken {
    type C = *const AuthToken;
    type Error = IpcError;

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        // TODO: do we actually need those de/serialize methods on auth token then
        Ok(Self {
            version: (*repr_c).version,
            signature: (*repr_c).signature.clone(),
            caveats: (*repr_c).caveats.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::deserialize;
    use rand::thread_rng;
    use unwrap::unwrap;

    use crate::{ClientFullId, SafeKey};

    fn generate_safe_key() -> SafeKey {
        SafeKey::client(ClientFullId::new_bls(&mut thread_rng()))
    }

    #[test]
    fn create_token_with_no_caveats() {
        let token = AuthToken::new().unwrap();

        // no caveat added, no signature added
        let caveat_len = token.caveats.len();
        assert_eq!(caveat_len, 0);
    }

    #[test]
    fn create_token_and_add_caveats_so_sig_changes() {
        let full_id = generate_safe_key();
        let mut token = unwrap!(AuthToken::new());

        // no caveat added, no signature added
        let caveat_len = token.clone().caveats.len();
        assert_eq!(caveat_len, 0);

        let caveat = ("expire".to_string(), "nowthen".to_string());

        token.add_caveat(caveat, &full_id).unwrap();

        let caveat_len2 = token.caveats.len();
        let sig = &unwrap!(token.signature.clone());

        assert_eq!(caveat_len2, 1);

        let caveat2 = ("expire2".to_string(), "nowthen222".to_string());
        unwrap!(token.add_caveat(caveat2, &full_id));
        let new_sig = &unwrap!(token.signature);
        assert_ne!(new_sig, sig);
    }

    #[test]
    fn create_token_re_serialize_and_check_validity() {
        let full_id = generate_safe_key();
        let public_id = full_id.public_id();

        let mut token = unwrap!(AuthToken::new());

        // no caveat added, no signature added
        let caveat_len = token.clone().caveats.len();
        assert_eq!(caveat_len, 0);

        let caveat = ("expire".to_string(), "nowthen".to_string());

        unwrap!(token.add_caveat(caveat, &full_id));

        let cereal = unwrap!(serialize(&token));
        let rehydrate: AuthToken = unwrap!(deserialize(&cereal));

        assert!(unwrap!(
            rehydrate.is_valid_for_public_key(&public_id.public_key())
        ));
    }

    #[test]
    fn create_token_re_serialize_and_check_validity_with_valid_checker() {
        let full_id = generate_safe_key();
        let public_id = full_id.public_id();

        let mut token = unwrap!(AuthToken::new());

        // no caveat added, no signature added
        let caveat_len = token.clone().caveats.len();
        assert_eq!(caveat_len, 0);

        let expire = "expire".to_string();

        let caveat = (expire.clone(), "nowthen".to_string());

        unwrap!(token.add_caveat(caveat, &full_id));

        let cereal = unwrap!(serialize(&token));
        let rehydrate: AuthToken = unwrap!(deserialize(&cereal));

        fn valid_checker(contents: CaveatContents) -> bool {
            contents.as_str() == "nowthen"
        }

        // sig validity
        assert!(unwrap!(
            rehydrate.is_valid_for_public_key(&public_id.public_key())
        ));

        // pass
        assert!(unwrap!(rehydrate.verify_caveat(&expire, valid_checker)));
    }

    #[test]
    fn create_token_re_serialize_and_check_validity_with_invalid_checker() {
        let full_id = generate_safe_key();
        let public_id = full_id.public_id();

        let mut token = unwrap!(AuthToken::new());

        // no caveat added, no signature added
        let caveat_len = token.clone().caveats.len();
        assert_eq!(caveat_len, 0);

        let expire = "expire".to_string();

        let caveat = (expire.clone(), "nowthen".to_string());

        unwrap!(token.add_caveat(caveat, &full_id));

        let cereal = unwrap!(serialize(&token));
        let rehydrate: AuthToken = unwrap!(deserialize(&cereal));

        fn invalid_checker(contents: CaveatContents) -> bool {
            contents.as_str() == "never surrender"
        }

        // sig validity
        assert!(unwrap!(
            rehydrate.is_valid_for_public_key(&public_id.public_key())
        ));

        // fail
        assert!(!unwrap!(rehydrate.verify_caveat(&expire, invalid_checker)));
    }

    #[test]
    fn create_token_re_serialize_and_try_to_check_nonexistant_caveat() {
        let full_id = generate_safe_key();
        let public_id = full_id.public_id();

        let mut token = unwrap!(AuthToken::new());

        // no caveat added, no signature added
        let caveat_len = token.clone().caveats.len();
        assert_eq!(caveat_len, 0);

        let expire = "expire".to_string();

        let caveat = (expire, "nowthen".to_string());

        unwrap!(token.add_caveat(caveat, &full_id));

        let cereal = unwrap!(serialize(&token));
        let rehydrate: AuthToken = unwrap!(deserialize(&cereal));

        fn valid_checker(contents: CaveatContents) -> bool {
            contents.as_str() == "nowthen"
        }

        // sig validity
        assert!(unwrap!(
            rehydrate.is_valid_for_public_key(&public_id.public_key())
        ));

        // fail
        assert!(!unwrap!(rehydrate.verify_caveat(
            &"non_existant_caveat".to_string(),
            valid_checker
        )));
    }

    #[test]
    fn token_check_against_another_app_fails() {
        let full_id = generate_safe_key();
        let mut token = unwrap!(AuthToken::new());

        // no caveat added, no signature added
        let caveat_len = token.clone().caveats.len();
        assert_eq!(caveat_len, 0);

        let caveat = ("expire".to_string(), "nowthen".to_string());

        unwrap!(token.add_caveat(caveat, &full_id));

        let cereal = unwrap!(serialize(&token));
        let rehydrate: AuthToken = unwrap!(deserialize(&cereal));
        let new_client_id = generate_safe_key();
        let public_id2 = new_client_id.public_id();

        assert!(!unwrap!(
            rehydrate.is_valid_for_public_key(&public_id2.public_key())
        ));
    }

    #[test]
    fn token_modify_and_sign_new_keys_fails() {
        let full_id = generate_safe_key();
        let public_id = full_id.public_id();

        let mut token = unwrap!(AuthToken::new());

        // no caveat added, no signature added
        let caveat_len = token.clone().caveats.len();
        assert_eq!(caveat_len, 0);

        let caveat = ("expire".to_string(), "nowthen".to_string());

        unwrap!(token.add_caveat(caveat, &full_id));

        let cereal = unwrap!(serialize(&token));

        let mut rehydrate: AuthToken = unwrap!(deserialize(&cereal));
        let new_client_id = generate_safe_key();

        // Original token is valid
        assert!(unwrap!(
            rehydrate.is_valid_for_public_key(&public_id.public_key())
        ));

        // trying to add a new caveat
        let caveat3 = ("expir3".to_string(), "nowthen222".to_string());

        // modify with another sig
        unwrap!(rehydrate.add_caveat(caveat3, &new_client_id));

        // check against original app key fails...
        let should_not_be_valid =
            unwrap!(rehydrate.is_valid_for_public_key(&public_id.public_key()));
        assert!(!should_not_be_valid);
    }

    #[test]
    fn token_modify_and_check_fails() {
        let full_id = generate_safe_key();
        let public_id = full_id.public_id();

        let mut token = unwrap!(AuthToken::new());

        // no caveat added, no signature added
        let caveat_len = token.clone().caveats.len();
        assert_eq!(caveat_len, 0);

        let caveat = ("expire".to_string(), "nowthen".to_string());

        unwrap!(token.add_caveat(caveat, &full_id));

        let cereal = unwrap!(serialize(&token));

        let mut rehydrate: AuthToken = unwrap!(deserialize(&cereal));

        // Original token is valid
        assert!(unwrap!(
            rehydrate.is_valid_for_public_key(&public_id.public_key())
        ));

        // modifying caveats .unwrap()fails sig
        let _ = rehydrate.caveats.drain(0..1);
        assert!(!unwrap!(
            rehydrate.is_valid_for_public_key(&public_id.public_key())
        ));
    }
}
