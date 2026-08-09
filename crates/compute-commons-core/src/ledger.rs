use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{digest, CommonsError, Result};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LedgerKind {
    BasicGrant,
    CommunityGrant,
    ComputeContributed,
    ComputeConsumed,
    Expired,
    Reversal,
    AdminCorrection,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub sequence: u64,
    pub member: String,
    pub kind: LedgerKind,
    pub amount: i64,
    pub task_id: Option<String>,
    pub previous_hash: String,
    pub hash: String,
}

#[derive(Default)]
pub struct CreditLedger {
    pub entries: Vec<LedgerEntry>,
    balances: HashMap<String, i64>,
    finalized_tasks: HashSet<String>,
}

impl CreditLedger {
    pub fn grant(&mut self, member: &str, amount: u64) -> Result<()> {
        let amount = i64::try_from(amount).map_err(|_| CommonsError::CreditOverflow)?;
        self.append(member, LedgerKind::BasicGrant, amount, None);
        Ok(())
    }

    pub fn settle_verified(
        &mut self,
        task_id: &str,
        owner: &str,
        node: &str,
        fixed_cost: u64,
    ) -> Result<bool> {
        if self.finalized_tasks.contains(task_id) {
            return Ok(false);
        }
        let fixed_cost = i64::try_from(fixed_cost).map_err(|_| CommonsError::CreditOverflow)?;
        if self.balance(owner) < fixed_cost {
            return Err(CommonsError::InsufficientCredit);
        }
        self.append(
            owner,
            LedgerKind::ComputeConsumed,
            -fixed_cost,
            Some(task_id),
        );
        self.append(
            node,
            LedgerKind::ComputeContributed,
            fixed_cost,
            Some(task_id),
        );
        self.finalized_tasks.insert(task_id.to_owned());
        Ok(true)
    }

    #[must_use]
    pub fn balance(&self, member: &str) -> i64 {
        *self.balances.get(member).unwrap_or(&0)
    }

    pub fn transfer(&mut self, _from: &str, _to: &str, _amount: u64) -> Result<()> {
        Err(CommonsError::TransferForbidden)
    }

    fn append(&mut self, member: &str, kind: LedgerKind, amount: i64, task_id: Option<&str>) {
        let previous_hash = self
            .entries
            .last()
            .map_or_else(|| "GENESIS".to_owned(), |e| e.hash.clone());
        let sequence = self.entries.len() as u64 + 1;
        let canonical =
            format!("{sequence}|{member}|{kind:?}|{amount}|{task_id:?}|{previous_hash}");
        let entry = LedgerEntry {
            sequence,
            member: member.to_owned(),
            kind,
            amount,
            task_id: task_id.map(str::to_owned),
            previous_hash,
            hash: digest(canonical.as_bytes()),
        };
        *self.balances.entry(member.to_owned()).or_default() += amount;
        self.entries.push(entry);
    }
}
