use anchor_lang::prelude::*;

declare_id!("RCPTxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

/// RCPT Anchor Program
///
/// Accepts batched Merkle roots from RCPT receipt stores and anchors them
/// on Solana. Any party can verify that a receipt existed at a specific time
/// by checking the Merkle proof against the on-chain root.
///
/// Storage model:
/// - Each anchor is a PDA derived from [b"anchor", authority, batch_id]
/// - Stores: merkle_root, receipt_count, timestamp, authority
/// - Immutable once created (no updates, no deletes)
///
/// Cost: ~0.002 SOL per anchor (~5KB account rent)
#[program]
pub mod rcpt_anchor {
    use super::*;

    /// Anchor a Merkle root on-chain.
    ///
    /// The authority signs the transaction, binding the root to their identity.
    /// batch_id is a unique identifier (ULID) for this batch of receipts.
    pub fn anchor_root(
        ctx: Context<AnchorRoot>,
        batch_id: String,
        merkle_root: [u8; 32],
        receipt_count: u32,
        metadata_uri: Option<String>,
    ) -> Result<()> {
        require!(batch_id.len() <= 26, RcptError::BatchIdTooLong);
        require!(receipt_count > 0, RcptError::EmptyBatch);

        let anchor_account = &mut ctx.accounts.anchor_account;
        anchor_account.authority = ctx.accounts.authority.key();
        anchor_account.batch_id = batch_id;
        anchor_account.merkle_root = merkle_root;
        anchor_account.receipt_count = receipt_count;
        anchor_account.anchored_at = Clock::get()?.unix_timestamp;
        anchor_account.metadata_uri = metadata_uri;
        anchor_account.bump = ctx.bumps.anchor_account;

        emit!(RootAnchored {
            authority: anchor_account.authority,
            batch_id: anchor_account.batch_id.clone(),
            merkle_root,
            receipt_count,
            anchored_at: anchor_account.anchored_at,
        });

        Ok(())
    }

    /// Verify a Merkle proof on-chain.
    ///
    /// Given a leaf hash, proof hashes, and the expected root,
    /// returns whether the proof is valid against the stored anchor.
    pub fn verify_proof(
        ctx: Context<VerifyProof>,
        leaf_hash: [u8; 32],
        proof: Vec<[u8; 32]>,
    ) -> Result<()> {
        let anchor_account = &ctx.accounts.anchor_account;
        let computed_root = compute_merkle_root(leaf_hash, &proof);

        require!(
            computed_root == anchor_account.merkle_root,
            RcptError::InvalidProof
        );

        emit!(ProofVerified {
            anchor: anchor_account.key(),
            leaf_hash,
            verified: true,
        });

        Ok(())
    }
}

// ── Accounts ───────────────────────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(batch_id: String)]
pub struct AnchorRoot<'info> {
    #[account(
        init,
        payer = authority,
        space = AnchorAccount::space(&batch_id),
        seeds = [b"anchor", authority.key().as_ref(), batch_id.as_bytes()],
        bump,
    )]
    pub anchor_account: Account<'info, AnchorAccount>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VerifyProof<'info> {
    pub anchor_account: Account<'info, AnchorAccount>,
}

// ── State ──────────────────────────────────────────────────────────────────

#[account]
pub struct AnchorAccount {
    /// The authority that anchored this root (their pubkey).
    pub authority: Pubkey,
    /// Unique batch identifier (ULID, max 26 chars).
    pub batch_id: String,
    /// SHA-256 Merkle root of the receipt batch.
    pub merkle_root: [u8; 32],
    /// Number of receipts in the batch.
    pub receipt_count: u32,
    /// Unix timestamp when the root was anchored.
    pub anchored_at: i64,
    /// Optional URI pointing to off-chain batch metadata.
    pub metadata_uri: Option<String>,
    /// PDA bump seed.
    pub bump: u8,
}

impl AnchorAccount {
    fn space(batch_id: &str) -> usize {
        8 +      // discriminator
        32 +     // authority (Pubkey)
        4 + batch_id.len() + // batch_id (String: 4-byte len + data)
        32 +     // merkle_root
        4 +      // receipt_count (u32)
        8 +      // anchored_at (i64)
        1 + 4 + 200 + // metadata_uri (Option<String>: 1 + 4 + max 200)
        1        // bump (u8)
    }
}

// ── Events ─────────────────────────────────────────────────────────────────

#[event]
pub struct RootAnchored {
    pub authority: Pubkey,
    pub batch_id: String,
    pub merkle_root: [u8; 32],
    pub receipt_count: u32,
    pub anchored_at: i64,
}

#[event]
pub struct ProofVerified {
    pub anchor: Pubkey,
    pub leaf_hash: [u8; 32],
    pub verified: bool,
}

// ── Errors ─────────────────────────────────────────────────────────────────

#[error_code]
pub enum RcptError {
    #[msg("Batch ID must be 26 characters or fewer")]
    BatchIdTooLong,
    #[msg("Batch must contain at least one receipt")]
    EmptyBatch,
    #[msg("Merkle proof verification failed")]
    InvalidProof,
}

// ── Merkle Verification ────────────────────────────────────────────────────

/// Compute the Merkle root from a leaf and proof path.
/// Uses sorted concatenation for determinism (matches the SDK implementation).
fn compute_merkle_root(leaf: [u8; 32], proof: &[[u8; 32]]) -> [u8; 32] {
    let mut current = leaf;

    for sibling in proof {
        let combined = if current <= *sibling {
            [current.as_slice(), sibling.as_slice()].concat()
        } else {
            [sibling.as_slice(), current.as_slice()].concat()
        };

        current = anchor_lang::solana_program::hash::hash(&combined).to_bytes();
    }

    current
}
