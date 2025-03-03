// Rust Dash Library
// Originally written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     For Bitcoin
// Updated for Dash in 2022 by
//     The Dash Core Developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Dash hash functions.
//!
//! This module provides utility functions related to hashing data, including
//! merkleization.
//!

use core::iter;

use prelude::*;

use io;
use core::cmp::min;

use hashes::Hash;
use consensus::encode::Encodable;

/// Calculates the merkle root of a list of *hashes*, inline (in place) in `hashes`.
///
/// In most cases, you'll want to use [dash_merkle_root] instead.
///
/// # Returns
/// - `None` if `hashes` is empty. The merkle root of an empty tree of hashes is undefined.
/// - `Some(hash)` if `hashes` contains one element. A single hash is by definition the merkle root.
/// - `Some(merkle_root)` if length of `hashes` is greater than one.
pub fn dash_merkle_root_inline<T>(hashes: &mut [T]) -> Option<T>
where
    T: Hash + Encodable,
          <T as Hash>::Engine: io::Write,
{
    match hashes.len() {
        0 => None,
        1 => Some(hashes[0]),
        _ => Some(merkle_root_r(hashes)),
    }
}

/// Calculates the merkle root of an iterator of *hashes*.
///
/// # Returns
/// - `None` if `hashes` is empty. The merkle root of an empty tree of hashes is undefined.
/// - `Some(hash)` if `hashes` contains one element. A single hash is by definition the merkle root.
/// - `Some(merkle_root)` if length of `hashes` is greater than one.
pub fn dash_merkle_root<T, I>(mut hashes: I) -> Option<T>
where
    T: Hash + Encodable,
    <T as Hash>::Engine: io::Write,
    I: Iterator<Item=T>,
{
    let first = hashes.next()?;
    let second = match hashes.next() {
        Some(second) => second,
        None => return Some(first),
    };

    let mut hashes = iter::once(first).chain(iter::once(second)).chain(hashes);

    // We need a local copy to pass to `merkle_root_r`. It's more efficient to do the first loop of
    // processing as we make the copy instead of copying the whole iterator.
    let (min, max) = hashes.size_hint();
    let mut alloc = Vec::with_capacity(max.unwrap_or(min) / 2 + 1);

    while let Some(hash1) = hashes.next() {
        // If the size is odd, use the last element twice.
        let hash2 = hashes.next().unwrap_or(hash1);
        let mut encoder = T::engine();
        hash1.consensus_encode(&mut encoder).expect("in-memory writers don't error");
        hash2.consensus_encode(&mut encoder).expect("in-memory writers don't error");
        alloc.push(T::from_engine(encoder));
    }

    Some(merkle_root_r(&mut alloc))
}

// `hashes` must contain at least one hash.
fn merkle_root_r<T>(hashes: &mut [T]) -> T
where
    T: Hash + Encodable,
    <T as Hash>::Engine: io::Write,
{
    if hashes.len() == 1 {
        return hashes[0]
    }

    for idx in 0..((hashes.len() + 1) / 2) {
        let idx1 = 2 * idx;
        let idx2 = min(idx1 + 1, hashes.len() - 1);
        let mut encoder = T::engine();
        hashes[idx1].consensus_encode(&mut encoder).expect("in-memory writers don't error");
        hashes[idx2].consensus_encode(&mut encoder).expect("in-memory writers don't error");
        hashes[idx] = T::from_engine(encoder);
    }
    let half_len = hashes.len() / 2 + hashes.len() % 2;

    merkle_root_r(&mut hashes[0..half_len])
}

#[cfg(test)]
mod tests {
    use consensus::encode::deserialize;
    use hashes::sha256d;

    use blockdata::block::Block;
    use super::*;

    #[test]
    fn both_merkle_root_functions_return_the_same_result() {
        // testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
        let segwit_block = include_bytes!("../../test_data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw");
        let block: Block = deserialize(&segwit_block[..]).expect("Failed to deserialize block");
        assert!(block.check_merkle_root()); // Sanity check.

        let hashes_iter = block.txdata.iter().map(|obj| obj.txid().as_hash());

        let mut hashes_array: [sha256d::Hash; 15] = [Default::default(); 15];
        for (i, hash) in hashes_iter.clone().enumerate() {
            hashes_array[i] = hash;
        }

        let from_iter = dash_merkle_root(hashes_iter);
        let from_array = dash_merkle_root_inline(&mut hashes_array);
        assert_eq!(from_iter, from_array);
    }
}
