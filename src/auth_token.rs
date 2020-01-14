// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![allow(unsafe_code)]

//! App authentication token generation

use crate::IpcError;
use crate::{FullId, PublicId, Signature};
use bincode::{deserialize, serialize};
use ffi_utils::ReprC;

use serde::{Deserialize, Serialize};

pub type CaveatName = String;
pub type CaveatContents = String; //| LabelCaveatContents;

/// Caveat to be optionally validate as a condition on the token
pub type Caveat = (CaveatName, CaveatContents);

/// Authentication Token, to be passed as means of authorisation to an app.
// To have signature of contents checked against the PublicKey in the account as validation.
#[repr(C)]
#[derive(Debug, Clone, Hash, Serialize, Deserialize, PartialEq, Eq)]
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
    pub fn new() -> Result<AuthToken, String> {
        let token = AuthToken::default();

        Ok(token)
    }
    /// Add a caveat to the token. This will update the token's signature.
    // TODO: Make this more generic? Can we just pass a sign func?
    pub fn add_caveat(&mut self, caveat: Caveat, full_id: &FullId) -> Result<(), String> {
        self.caveats.push(caveat);
        self.sign(&full_id)?;

        Ok(())
    }
    /// Sign the token
    fn sign(&mut self, full_id: &FullId) -> Result<(), String> {
        // clear any signature first.
        self.signature = None;

        let serialized_token = serde_json::to_string(&self).unwrap();
        let sig = full_id.sign(&serialized_token.into_bytes());

        assert_eq!(&sig, &sig);

        self.signature = Some(sig);

        Ok(())
    }
    // TODO: do we actually need this?
    /// serialize the token to json
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        let token = serialize(&self).unwrap();
        Ok(token)
    }
    /// Deserialize the token from a json string
    pub fn deserialize(cereal: &[u8]) -> Result<AuthToken, String> {
        let token: AuthToken = deserialize(cereal).unwrap();
        Ok(token)
    }
    /// Check if the token signature is valid for a given public key
    pub fn is_valid_for_public_id(&mut self, public_id: &PublicId) -> bool {
        let mut token_to_sign = self.clone();

        let public_key = public_id.public_key();
        //clear signature for checks
        token_to_sign.signature = None;
        let serialised_token = serde_json::to_string(&token_to_sign).unwrap();
        let raw_sig = self.signature.as_ref().unwrap();

        let sig: Signature = raw_sig.clone();

        match public_key.verify(&sig, &serialised_token) {
            Ok(()) => true,
            Err(_) => false,
        }
    }

    /// Constructs FFI wrapper for the native Rust object, consuming self.
    pub fn into_repr_c(self) -> Result<AuthToken, IpcError> {
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
    use rand::thread_rng;

    use crate::{AppFullId, ClientFullId};

    fn generate_safe_key() -> FullId {
        let owner = ClientFullId::new_bls(&mut thread_rng()).public_id().clone();
        let id = AppFullId::new_bls(&mut thread_rng(), owner);

        FullId::App(id)
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
        let mut token = AuthToken::new().unwrap();

        // no caveat added, no signature added
        let caveat_len = token.clone().caveats.len();
        assert_eq!(caveat_len, 0);

        let caveat = ("expire".to_string(), "nowthen".to_string());

        token.add_caveat(caveat, &full_id).unwrap();

        let caveat_len2 = token.caveats.len();
        let sig = &token.signature.clone().unwrap();

        assert_eq!(caveat_len2, 1);

        let caveat2 = ("expire2".to_string(), "nowthen222".to_string());
        token.add_caveat(caveat2, &full_id).unwrap();
        let new_sig = &token.signature.unwrap();
        assert_ne!(new_sig, sig);
    }

    #[test]
    fn create_token_re_serialize_and_check_validity() {
        let full_id = generate_safe_key();
        let public_id = full_id.public_id();

        let mut token = AuthToken::new().unwrap();

        // no caveat added, no signature added
        let caveat_len = token.clone().caveats.len();
        assert_eq!(caveat_len, 0);

        let caveat = ("expire".to_string(), "nowthen".to_string());

        token.add_caveat(caveat, &full_id).unwrap();

        let cereal = &token.serialize().unwrap();
        let mut rehydrate = AuthToken::deserialize(&cereal).unwrap();

        assert!(rehydrate.is_valid_for_public_id(&public_id));
    }

    #[test]
    fn token_check_against_naother_app_fails() {
        let full_id = generate_safe_key();
        let mut token = AuthToken::new().unwrap();

        // no caveat added, no signature added
        let caveat_len = token.clone().caveats.len();
        assert_eq!(caveat_len, 0);

        let caveat = ("expire".to_string(), "nowthen".to_string());

        token.add_caveat(caveat, &full_id).unwrap();

        let cereal = &token.serialize().unwrap();
        let mut rehydrate = AuthToken::deserialize(&cereal).unwrap();
        let new_client_id = generate_safe_key();
        let public_id2 = new_client_id.public_id();

        assert!(!rehydrate.is_valid_for_public_id(&public_id2));
    }

    #[test]
    fn token_modify_and_sign_new_keys_fails() {
        let full_id = generate_safe_key();
        let public_id = full_id.public_id();

        let mut token = AuthToken::new().unwrap();

        // no caveat added, no signature added
        let caveat_len = token.clone().caveats.len();
        assert_eq!(caveat_len, 0);

        let caveat = ("expire".to_string(), "nowthen".to_string());

        token.add_caveat(caveat, &full_id).unwrap();

        let cereal = &token.serialize().unwrap();

        let mut rehydrate = AuthToken::deserialize(&cereal).unwrap();
        let new_client_id = generate_safe_key();

        // Original token is valid
        assert!(rehydrate.is_valid_for_public_id(&public_id));

        // trying to add a new caveat
        let caveat3 = ("expir3".to_string(), "nowthen222".to_string());

        // modify with another sig
        rehydrate.add_caveat(caveat3, &new_client_id).unwrap();

        // check against original app key fails...
        let should_not_be_valid = rehydrate.is_valid_for_public_id(&public_id);
        assert!(!should_not_be_valid);
    }

    #[test]
    fn token_modify_and_check_fails() {
        let full_id = generate_safe_key();
        let public_id = full_id.public_id();

        let mut token = AuthToken::new().unwrap();

        // no caveat added, no signature added
        let caveat_len = token.clone().caveats.len();
        assert_eq!(caveat_len, 0);

        let caveat = ("expire".to_string(), "nowthen".to_string());

        token.add_caveat(caveat, &full_id).unwrap();

        let cereal = &token.serialize().unwrap();

        let mut rehydrate = AuthToken::deserialize(&cereal).unwrap();

        // Original token is valid
        assert!(rehydrate.is_valid_for_public_id(&public_id));

        // modifying caveats fails sig
        let _ = rehydrate.caveats.drain(0..1);
        assert!(!rehydrate.is_valid_for_public_id(&public_id));
    }
}
