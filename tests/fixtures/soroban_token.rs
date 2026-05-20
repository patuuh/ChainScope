#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, contracterror, symbol_short,
    Address, Env, String, Vec, Map, log,
    token::{self, Client as TokenClient, StellarAssetClient},
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum TokenError {
    NotAuthorized = 1,
    InsufficientBalance = 2,
    InvalidAmount = 3,
    AlreadyInitialized = 4,
    NotInitialized = 5,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Admin,
    Balance(Address),
    Allowance(Address, Address),
    TotalSupply,
    Name,
    Symbol,
    Decimals,
    Paused,
    Nonce(Address),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenState {
    Uninitialized,
    Active,
    Paused,
    Deprecated,
}

#[contract]
pub struct StellarToken;

#[contractimpl]
impl StellarToken {
    /// Initialize the token contract
    pub fn initialize(
        env: Env,
        admin: Address,
        name: String,
        symbol: String,
        decimals: u32,
    ) {
        // Check not already initialized
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }

        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Name, &name);
        env.storage().instance().set(&DataKey::Symbol, &symbol);
        env.storage().instance().set(&DataKey::Decimals, &decimals);
        env.storage().instance().set(&DataKey::TotalSupply, &0i128);

        env.events().publish(
            (symbol_short!("init"), admin.clone()),
            (name, symbol, decimals),
        );
    }

    /// Mint tokens to an address (admin only)
    pub fn mint(env: Env, to: Address, amount: i128) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        // BUG: No amount > 0 check (G4)
        let balance: i128 = env.storage()
            .persistent()
            .get(&DataKey::Balance(to.clone()))
            .unwrap_or(0);

        // BUG: Unchecked arithmetic (B4)
        let new_balance = balance + amount;
        env.storage().persistent().set(&DataKey::Balance(to.clone()), &new_balance);

        let total: i128 = env.storage().instance().get(&DataKey::TotalSupply).unwrap();
        let new_total = total + amount;
        env.storage().instance().set(&DataKey::TotalSupply, &new_total);

        // Correct: extends TTL on persistent storage
        env.storage().persistent().extend_ttl(
            &DataKey::Balance(to.clone()),
            1000,
            5000,
        );

        env.events().publish(
            (symbol_short!("mint"), to),
            amount,
        );
    }

    /// Transfer tokens between addresses
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();

        if amount <= 0 {
            panic_with_error!(env, TokenError::InvalidAmount);
        }

        let from_balance: i128 = env.storage()
            .persistent()
            .get(&DataKey::Balance(from.clone()))
            .unwrap();

        if from_balance < amount {
            panic_with_error!(env, TokenError::InsufficientBalance);
        }

        let to_balance: i128 = env.storage()
            .persistent()
            .get(&DataKey::Balance(to.clone()))
            .unwrap_or(0);

        // Unchecked subtraction and addition (B4)
        env.storage().persistent().set(
            &DataKey::Balance(from.clone()),
            &(from_balance - amount),
        );
        env.storage().persistent().set(
            &DataKey::Balance(to.clone()),
            &(to_balance + amount),
        );

        // BUG: Missing extend_ttl on persistent writes (C7)

        env.events().publish(
            (symbol_short!("xfer"), from, to),
            amount,
        );
    }

    /// Approve spender to transfer tokens
    pub fn approve(
        env: Env,
        from: Address,
        spender: Address,
        amount: i128,
        expiration_ledger: u32,
    ) {
        from.require_auth();

        // BUG: No zero-first pattern (G1 - approve race condition)
        env.storage().persistent().set(
            &DataKey::Allowance(from.clone(), spender.clone()),
            &amount,
        );

        env.events().publish(
            (symbol_short!("approve"), from, spender),
            (amount, expiration_ledger),
        );
    }

    /// Transfer tokens using allowance
    pub fn transfer_from(
        env: Env,
        spender: Address,
        from: Address,
        to: Address,
        amount: i128,
    ) {
        spender.require_auth();

        let allowance: i128 = env.storage()
            .persistent()
            .get(&DataKey::Allowance(from.clone(), spender.clone()))
            .unwrap_or(0);

        if allowance < amount {
            panic_with_error!(env, TokenError::NotAuthorized);
        }

        // Update allowance
        env.storage().persistent().set(
            &DataKey::Allowance(from.clone(), spender.clone()),
            &(allowance - amount),
        );

        // Execute transfer
        let from_balance: i128 = env.storage()
            .persistent()
            .get(&DataKey::Balance(from.clone()))
            .unwrap();
        let to_balance: i128 = env.storage()
            .persistent()
            .get(&DataKey::Balance(to.clone()))
            .unwrap_or(0);

        env.storage().persistent().set(
            &DataKey::Balance(from.clone()),
            &(from_balance - amount),
        );
        env.storage().persistent().set(
            &DataKey::Balance(to.clone()),
            &(to_balance + amount),
        );

        env.events().publish(
            (symbol_short!("xfer"), from, to),
            amount,
        );
    }

    /// Burn tokens
    pub fn burn(env: Env, from: Address, amount: i128) {
        from.require_auth();

        let balance: i128 = env.storage()
            .persistent()
            .get(&DataKey::Balance(from.clone()))
            .unwrap();

        env.storage().persistent().set(
            &DataKey::Balance(from.clone()),
            &(balance - amount),
        );

        let total: i128 = env.storage().instance().get(&DataKey::TotalSupply).unwrap();
        env.storage().instance().set(&DataKey::TotalSupply, &(total - amount));

        // BUG: Missing burn event (G2)
    }

    /// Set a new admin
    pub fn set_admin(env: Env, new_admin: Address) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &new_admin);

        env.events().publish(
            (symbol_short!("admin"),),
            new_admin,
        );
    }

    /// Read-only: get balance
    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(id))
            .unwrap_or(0)
    }

    /// Read-only: get total supply
    pub fn total_supply(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0)
    }

    /// Read-only: get name
    pub fn name(env: Env) -> String {
        env.storage().instance().get(&DataKey::Name).unwrap()
    }

    /// Read-only: get symbol
    pub fn symbol(env: Env) -> String {
        env.storage().instance().get(&DataKey::Symbol).unwrap()
    }

    /// Read-only: get decimals
    pub fn decimals(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::Decimals).unwrap()
    }

    /// VULNERABLE: Pause without auth check (A2)
    pub fn pause(env: Env) {
        // Missing: admin.require_auth()
        env.storage().instance().set(&DataKey::Paused, &true);
    }

    /// Store nonce in temporary storage
    pub fn use_nonce(env: Env, user: Address, nonce: u64) {
        user.require_auth();

        // BUG: Nonce in temporary storage can expire and be replayed (C3/C8)
        if env.storage().temporary().has(&DataKey::Nonce(user.clone())) {
            panic!("nonce already used");
        }
        env.storage().temporary().set(&DataKey::Nonce(user), &nonce);
    }

    /// VULNERABLE: Uses PRNG for security decision (H1)
    pub fn random_airdrop(env: Env, recipients: Vec<Address>, total_amount: i128) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        let count = recipients.len();
        for i in 0..count {
            let random_share = env.prng().gen_range::<u64>(1..100);
            let share_amount = (total_amount * random_share as i128) / 100;
            let recipient = recipients.get(i).unwrap();

            let balance: i128 = env.storage()
                .persistent()
                .get(&DataKey::Balance(recipient.clone()))
                .unwrap_or(0);
            env.storage().persistent().set(
                &DataKey::Balance(recipient),
                &(balance + share_amount),
            );
        }
    }
}
