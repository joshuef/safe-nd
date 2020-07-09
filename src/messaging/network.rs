// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    AccountId, Address, DebitAgreementProof, Error, IDataAddress, MessageId, Signature,
    SignatureShare, SignedTransfer, TransferId, TransferValidated, XorName,
};
use serde::{Deserialize, Serialize};

///
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NetworkCmd {
    ///
    ReceiveWorker {
        ///
        new_node_id: XorName,
        ///
        account_id: AccountId,
        ///
        counter: Vec<u8>,
    },
    ///
    DuplicateChunk {
        ///
        address: IDataAddress,
        ///
        new_holder: XorName,
        ///
        message_id: MessageId,
        ///
        signature: Option<(usize, SignatureShare)>,
    },
    ///
    InitiateRewardPayout {
        ///
        signed_transfer: SignedTransfer,
        ///
        message_id: MessageId,
    },
    ///
    FinaliseRewardPayout {
        ///
        debit_agreement: DebitAgreementProof,
        ///
        message_id: MessageId,
    },
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NetworkEvent {
    /// Wrapper for a duplicate completion response, from a node to elders.
    DuplicationComplete {
        ///
        chunk: IDataAddress,
        ///
        message_id: MessageId,
        ///
        proof: Option<Signature>,
    },
    ///
    RewardPayoutValidated {
        ///
        event: TransferValidated,
        ///
        message_id: MessageId,
    },
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NetworkCmdError {
    ///
    WorkerReception {
        ///
        account_id: AccountId,
        ///
        error: Error,
    },
    ///
    DuplicateChunk {
        ///
        address: IDataAddress,
        ///
        error: Error,
    },
    ///
    RewardPayoutInitiation {
        ///
        id: TransferId,
        ///
        account: AccountId,
    },
    ///
    RewardPayoutFinalisation {
        ///
        id: TransferId,
        ///
        account: AccountId,
    },
}

impl NetworkCmd {
    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> Address {
        use Address::*;
        use NetworkCmd::*;
        match self {
            ReceiveWorker { new_node_id, .. } => Section(*new_node_id),
            DuplicateChunk { new_holder, .. } => Node(*new_holder),
            InitiateRewardPayout {
                signed_transfer, ..
            } => Section(signed_transfer.from().into()),
            FinaliseRewardPayout {
                debit_agreement, ..
            } => Section(debit_agreement.from().into()),
        }
    }
}

impl NetworkEvent {
    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> Address {
        use Address::*;
        use NetworkEvent::*;
        match self {
            DuplicationComplete { chunk, .. } => Section(*chunk.name()),
            RewardPayoutValidated { event, .. } => Section(event.from().into()),
        }
    }
}