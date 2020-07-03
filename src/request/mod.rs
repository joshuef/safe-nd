// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod client_req;
mod idata;
mod login_packet;
mod mdata;
mod money;
mod sdata;

pub use self::login_packet::{LoginPacket, LoginPacketRequest, MAX_LOGIN_PACKET_BYTES};
use crate::{Error, Response, XorName};
pub use client_req::ClientRequest;
pub use idata::IDataRequest;
pub use mdata::MDataRequest;
pub use money::MoneyRequest;
pub use sdata::SDataRequest;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

/// The type of a `Request`.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Type {
    /// Request is a Read of public data.
    PublicRead,
    /// Request is a Read of private data.
    PrivateRead,
    /// Request is a Write.
    Write,
    /// Request is a Transfer.
    Transfer,
    // /// Request to validate a Transfer of money.
    // TransferValidation, // TODO: fix..
    // /// Request to register a validated Transfer of money.
    // TransferRegistration, // TODO: fix..
}

/// The kind of authorisation needed for a request.
pub enum AuthorisationKind {
    /// Authorisation for data requests.
    Data(DataAuthKind),
    /// Authorisation for money requests.
    Money(MoneyAuthKind),
    /// Miscellaneous authorisation kinds.
    /// NB: Not very well categorized yet
    Misc(MiscAuthKind),
    /// When none required.
    None,
}

/// Authorisation for data requests.
pub enum DataAuthKind {
    /// Read of public data.
    PublicRead,
    /// Read of private data.
    PrivateRead,
    /// Write of data/metadata.
    Write,
}

/// Authorisation for money requests.
pub enum MoneyAuthKind {
    /// Request to get key balance.
    ReadBalance,
    /// Request to get key transfer history.
    ReadHistory,
    /// Request to transfer money from key.
    Transfer,
}

/// Miscellaneous authorisation kinds.
/// NB: Not very well categorized yet
pub enum MiscAuthKind {
    /// Request to manage app keys.
    ManageAppKeys,
    /// Request to mutate and transfer money from key.
    WriteAndTransfer,
}

/// RPC Request that is sent to vaults.
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Clone, Serialize, Deserialize)]
pub enum Request {
    /// ImmutableData request
    IData(IDataRequest),
    /// MutableData request
    MData(MDataRequest),
    /// Sequence request
    SData(SDataRequest),
    /// Money request
    Money(MoneyRequest),
    /// LoginPacket request
    LoginPacket(LoginPacketRequest),
    /// Client (Owner) request
    Client(ClientRequest),
}

impl Request {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use Request::*;
        match self {
            IData(req) => req.get_type(),
            MData(req) => req.get_type(),
            SData(req) => req.get_type(),
            Money(req) => req.get_type(),
            LoginPacket(req) => req.get_type(),
            Client(req) => req.get_type(),
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use Request::*;
        match self {
            IData(req) => req.error_response(error),
            MData(req) => req.error_response(error),
            SData(req) => req.error_response(error),
            Money(req) => req.error_response(error),
            LoginPacket(req) => req.error_response(error),
            Client(req) => req.error_response(error),
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use Request::*;
        match self {
            IData(req) => req.authorisation_kind(),
            MData(req) => req.authorisation_kind(),
            SData(req) => req.authorisation_kind(),
            Money(req) => req.authorisation_kind(),
            LoginPacket(req) => req.authorisation_kind(),
            Client(req) => req.authorisation_kind(),
        }
    }

    /// Returns the address of the destination for `request`.
    pub fn dest_address(&self) -> Option<Cow<XorName>> {
        use Request::*;
        match self {
            IData(req) => req.dest_address(),
            MData(req) => req.dest_address(),
            SData(req) => req.dest_address(),
            Money(req) => req.dest_address(),
            LoginPacket(req) => req.dest_address(),
            Client(req) => req.dest_address(),
        }
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use Request::*;

        match self {
            IData(req) => write!(formatter, "{:?}", req),
            MData(req) => write!(formatter, "{:?}", req),
            SData(req) => write!(formatter, "{:?}", req),
            Money(req) => write!(formatter, "{:?}", req),
            LoginPacket(req) => write!(formatter, "{:?}", req),
            Client(req) => write!(formatter, "{:?}", req),
        }
    }
}
