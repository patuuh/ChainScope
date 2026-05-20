#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, contracterror, contractclient,
    symbol_short, Address, BytesN, Env, Map, Vec,
    token::Client as TokenClient,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VaultError {
    NotAuthorized = 1,
    InsufficientShares = 2,
    VaultPaused = 3,
    InvalidAmount = 4,
    AlreadyInitialized = 5,
    SlippageExceeded = 6,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VaultState {
    Uninitialized,
    Active,
    Paused,
    Deprecated,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Admin,
    Token,
    TotalShares,
    TotalAssets,
    Shares(Address),
    State,
    FeeRate,
    FeeCollector,
    PriceOracle,
    UpgradeHash,
    DepositHistory,
}

#[contractclient(name = "OracleClient")]
pub trait Oracle {
    fn get_price(env: Env, asset: Address) -> i128;
}

#[contract]
pub struct DeFiVault;

#[contractimpl]
impl DeFiVault {
    /// Initialize the vault
    pub fn initialize(
        env: Env,
        admin: Address,
        token: Address,
        fee_rate: u32,
        oracle: Address,
    ) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(env, VaultError::AlreadyInitialized);
        }

        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Token, &token);
        env.storage().instance().set(&DataKey::FeeRate, &fee_rate);
        env.storage().instance().set(&DataKey::PriceOracle, &oracle);
        env.storage().instance().set(&DataKey::TotalShares, &0i128);
        env.storage().instance().set(&DataKey::TotalAssets, &0i128);
        env.storage().instance().set(&DataKey::State, &VaultState::Active);

        env.events().publish(
            (symbol_short!("init"), admin.clone()),
            (token, fee_rate),
        );
    }

    /// Deposit assets and receive shares
    pub fn deposit(env: Env, user: Address, amount: i128) -> i128 {
        user.require_auth();
        Self::require_active(&env);

        if amount <= 0 {
            panic_with_error!(env, VaultError::InvalidAmount);
        }

        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let total_shares: i128 = env.storage().instance().get(&DataKey::TotalShares).unwrap();
        let total_assets: i128 = env.storage().instance().get(&DataKey::TotalAssets).unwrap();

        // Calculate shares — BUG: division before multiplication (B2)
        let shares = if total_shares == 0 {
            amount
        } else {
            (amount / total_assets) * total_shares
        };

        // Transfer tokens to vault
        let token_client = TokenClient::new(&env, &token);
        token_client.transfer(&user, &env.current_contract_address(), &amount);

        // BUG: State write AFTER cross-contract call (F2 - reentrancy)
        let user_shares: i128 = env.storage()
            .persistent()
            .get(&DataKey::Shares(user.clone()))
            .unwrap_or(0);
        env.storage().persistent().set(
            &DataKey::Shares(user.clone()),
            &(user_shares + shares),
        );
        env.storage().instance().set(&DataKey::TotalShares, &(total_shares + shares));
        env.storage().instance().set(&DataKey::TotalAssets, &(total_assets + amount));

        // BUG: Unbounded instance storage growing (C1)
        let mut history: Vec<(Address, i128)> = env.storage()
            .instance()
            .get(&DataKey::DepositHistory)
            .unwrap_or(Vec::new(&env));
        history.push_back((user.clone(), amount));
        env.storage().instance().set(&DataKey::DepositHistory, &history);

        env.storage().persistent().extend_ttl(
            &DataKey::Shares(user.clone()),
            1000,
            5000,
        );

        env.events().publish(
            (symbol_short!("deposit"), user),
            (amount, shares),
        );

        shares
    }

    /// Withdraw assets by burning shares
    pub fn withdraw(env: Env, user: Address, shares: i128) -> i128 {
        user.require_auth();
        Self::require_active(&env);

        let user_shares: i128 = env.storage()
            .persistent()
            .get(&DataKey::Shares(user.clone()))
            .unwrap();

        if user_shares < shares {
            panic_with_error!(env, VaultError::InsufficientShares);
        }

        let total_shares: i128 = env.storage().instance().get(&DataKey::TotalShares).unwrap();
        let total_assets: i128 = env.storage().instance().get(&DataKey::TotalAssets).unwrap();

        // Calculate withdrawal amount
        let fee_rate: u32 = env.storage().instance().get(&DataKey::FeeRate).unwrap();
        let gross_amount = (shares * total_assets) / total_shares;
        let fee = (gross_amount * fee_rate as i128) / 10000;
        let net_amount = gross_amount - fee;

        // Update state BEFORE cross-contract call (correct pattern)
        env.storage().persistent().set(
            &DataKey::Shares(user.clone()),
            &(user_shares - shares),
        );
        env.storage().instance().set(&DataKey::TotalShares, &(total_shares - shares));
        env.storage().instance().set(&DataKey::TotalAssets, &(total_assets - gross_amount));

        // Transfer tokens to user
        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let token_client = TokenClient::new(&env, &token);
        token_client.transfer(&env.current_contract_address(), &user, &net_amount);

        env.events().publish(
            (symbol_short!("wdraw"), user),
            (shares, net_amount),
        );

        net_amount
    }

    /// Get price from oracle — no staleness check (H3)
    pub fn get_asset_price(env: Env) -> i128 {
        let oracle: Address = env.storage().instance().get(&DataKey::PriceOracle).unwrap();
        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();

        let oracle_client = OracleClient::new(&env, &oracle);
        let price = oracle_client.get_price(&token);

        price
    }

    /// VULNERABLE: Upgrade without auth (A3/I1)
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        // Missing: admin.require_auth()
        env.deployer().update_current_contract_wasm(new_wasm_hash);
        // Missing: event emission (I3)
    }

    /// Set fee rate — has auth
    pub fn set_fee_rate(env: Env, new_rate: u32) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        env.storage().instance().set(&DataKey::FeeRate, &new_rate);
    }

    /// VULNERABLE: set_admin with require_auth_for_args mismatch
    pub fn set_admin(env: Env, current_admin: Address, new_admin: Address) {
        // Uses require_auth_for_args but with potentially mismatched args
        current_admin.require_auth_for_args(
            (new_admin.clone(),).into_val(&env),
        );

        env.storage().instance().set(&DataKey::Admin, &new_admin);

        env.events().publish(
            (symbol_short!("admin"),),
            new_admin,
        );
    }

    /// VULNERABLE: Unbounded loop over storage (J1)
    pub fn batch_distribute(env: Env, recipients: Vec<Address>, amounts: Vec<i128>) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let token_client = TokenClient::new(&env, &token);

        // No length bound check
        for i in 0..recipients.len() {
            let recipient = recipients.get(i).unwrap();
            let amount = amounts.get(i).unwrap();
            token_client.transfer(
                &env.current_contract_address(),
                &recipient,
                &amount,
            );
        }
    }

    /// VULNERABLE: Uses XOR instead of pow (B3)
    pub fn calculate_compound(env: Env, principal: i128, rate: i128, periods: u32) -> i128 {
        // BUG: ^ is XOR in Rust, not exponentiation
        let factor = (1 + rate) ^ periods as i128;
        let result = principal * factor;
        result
    }

    /// VULNERABLE: Arbitrary contract invocation (F4)
    pub fn execute_strategy(env: Env, strategy_contract: Address, amount: i128) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        // User-supplied contract address — no validation
        env.invoke_contract::<()>(
            &strategy_contract,
            &symbol_short!("exec"),
            (amount,).into_val(&env),
        );
    }

    /// VULNERABLE: Uses ledger timestamp for randomness (H2)
    pub fn select_winner(env: Env, participants: Vec<Address>) -> Address {
        let timestamp = env.ledger().timestamp();
        let index = (timestamp % participants.len() as u64) as u32;
        participants.get(index).unwrap()
    }

    /// Internal: check vault is active
    fn require_active(env: &Env) {
        let state: VaultState = env.storage()
            .instance()
            .get(&DataKey::State)
            .unwrap_or(VaultState::Uninitialized);

        if state != VaultState::Active {
            panic_with_error!(env, VaultError::VaultPaused);
        }
    }

    /// Pause the vault
    pub fn pause(env: Env) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        env.storage().instance().set(&DataKey::State, &VaultState::Paused);

        env.events().publish(
            (symbol_short!("pause"),),
            true,
        );
    }

    /// Resume the vault
    pub fn resume(env: Env) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        env.storage().instance().set(&DataKey::State, &VaultState::Active);

        env.events().publish(
            (symbol_short!("resume"),),
            true,
        );
    }

    /// Read-only: get user shares
    pub fn shares(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Shares(user))
            .unwrap_or(0)
    }

    /// Read-only: get total shares
    pub fn total_shares(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::TotalShares).unwrap_or(0)
    }

    /// VULNERABLE: unsafe block in contract (E6)
    pub fn unsafe_decode(env: Env, data: BytesN<32>) -> u64 {
        unsafe {
            let ptr = data.to_array().as_ptr() as *const u64;
            *ptr
        }
    }
}
