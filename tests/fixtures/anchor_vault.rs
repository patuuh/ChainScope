use anchor_lang::prelude::*;

declare_id!("Vault111111111111111111111111111111111111111");

#[program]
pub mod vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, bump: u8) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.total_deposits = 0;
        vault.state = VaultState::Active;
        vault.bump = bump;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        require!(ctx.accounts.vault.state == VaultState::Active, VaultError::NotActive);
        require!(amount > 0, VaultError::ZeroAmount);

        let vault = &mut ctx.accounts.vault;
        vault.total_deposits += amount;

        let cpi_ctx = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.user.to_account_info(),
                to: ctx.accounts.vault_token.to_account_info(),
            },
        );
        anchor_lang::system_program::transfer(cpi_ctx, amount)?;

        emit!(DepositEvent {
            user: ctx.accounts.user.key(),
            amount,
        });

        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        require!(ctx.accounts.vault.state == VaultState::Active, VaultError::NotActive);

        let vault = &mut ctx.accounts.vault;
        vault.total_deposits -= amount;

        let seeds = &[b"vault", &[vault.bump]];
        let signer_seeds = &[&seeds[..]];

        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.vault_token.to_account_info(),
                to: ctx.accounts.user.to_account_info(),
            },
            signer_seeds,
        );
        anchor_lang::system_program::transfer(cpi_ctx, amount)?;
        Ok(())
    }

    pub fn pause(ctx: Context<AdminOnly>) -> Result<()> {
        require!(ctx.accounts.vault.state == VaultState::Active, VaultError::NotActive);
        ctx.accounts.vault.state = VaultState::Paused;
        Ok(())
    }

    pub fn update_fee(ctx: Context<UpdateFee>, new_fee: u64) -> Result<()> {
        let config = &mut ctx.accounts.config;
        let total = config.base_fee + new_fee;
        config.fee = total;
        Ok(())
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub enum VaultState {
    Active,
    Paused,
    Closed,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub total_deposits: u64,
    pub state: VaultState,
    pub bump: u8,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 32 + 8 + 1 + 1, seeds = [b"vault", authority.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub user: Signer<'info>,
    /// CHECK: vault token account
    #[account(mut)]
    pub vault_token: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub authority: Signer<'info>,
    /// CHECK: vault token account
    #[account(mut)]
    pub vault_token: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(mut, has_one = authority, close = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateFee<'info> {
    #[account(init_if_needed, payer = authority, space = 8 + 32 + 8 + 8, seeds = [b"config"], bump)]
    pub config: Account<'info, FeeConfig>,
    #[account(mut, owner = token_program)]
    pub fee_destination: AccountInfo<'info>,
    #[account(mut, constraint = authority.key() == config.admin)]
    pub authority: Signer<'info>,
    /// CHECK: unchecked oracle
    pub oracle: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct FeeConfig {
    pub admin: Pubkey,
    pub fee: u64,
    pub base_fee: u64,
}

#[event]
pub struct DepositEvent {
    pub user: Pubkey,
    pub amount: u64,
}

#[error_code]
pub enum VaultError {
    #[msg("Vault is not active")]
    NotActive,
    #[msg("Amount must be > 0")]
    ZeroAmount,
}
