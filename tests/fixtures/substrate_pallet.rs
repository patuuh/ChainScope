#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type Currency: frame_support::traits::Currency<Self::AccountId>;
        type GovernanceOrigin: EnsureOrigin<Self::RuntimeOrigin>;
    }

    #[pallet::storage]
    #[pallet::getter(fn proposals)]
    pub type Proposals<T: Config> = StorageMap<_, Blake2_128Concat, u32, Proposal<T::AccountId>>;

    #[pallet::storage]
    #[pallet::getter(fn proposal_count)]
    pub type ProposalCount<T> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn total_locked)]
    pub type TotalLocked<T> = StorageValue<_, u128, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn pending_actions)]
    pub type PendingActions<T> = StorageValue<_, Vec<u8>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn votes)]
    pub type Votes<T: Config> = StorageDoubleMap<_, Blake2_128Concat, u32, Blake2_128Concat, T::AccountId, bool>;

    #[pallet::storage]
    #[pallet::getter(fn active_voters)]
    pub type ActiveVoters<T: Config> = CountedStorageMap<_, Blake2_128Concat, T::AccountId, u32>;

    #[pallet::storage]
    #[pallet::getter(fn description)]
    pub type Description<T> = StorageValue<_, String, ValueQuery>;

    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub enum ProposalState {
        Pending,
        Active,
        Executed,
        Cancelled,
    }

    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub struct Proposal<AccountId> {
        pub proposer: AccountId,
        pub state: ProposalState,
        pub amount: u128,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ProposalCreated { id: u32, proposer: T::AccountId },
        ProposalActivated { id: u32 },
        ProposalExecuted { id: u32, amount: u128 },
        FundsLocked { who: T::AccountId, amount: u128 },
        ProposalCancelled { id: u32 },
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::create_proposal())]
        #[transactional]
        pub fn create_proposal(origin: OriginFor<T>, amount: u128) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let id = <ProposalCount<T>>::get();
            let proposal = Proposal {
                proposer: who.clone(),
                state: ProposalState::Pending,
                amount,
            };
            Proposals::<T>::insert(id, proposal);
            ProposalCount::<T>::put(id + 1);
            Self::deposit_event(Event::ProposalCreated { id, proposer: who });
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(10_000)]
        pub fn activate_proposal(origin: OriginFor<T>, id: u32) -> DispatchResult {
            ensure_root(origin)?;
            Proposals::<T>::try_mutate(id, |maybe_proposal| -> DispatchResult {
                let proposal = maybe_proposal.as_mut().ok_or(Error::<T>::NotFound)?;
                ensure!(proposal.state == ProposalState::Pending, Error::<T>::InvalidState);
                proposal.state = ProposalState::Active;
                Self::deposit_event(Event::ProposalActivated { id });
                Ok(())
            })
        }

        #[pallet::weight(10_000)]
        pub fn execute_proposal(origin: OriginFor<T>, id: u32) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Proposals::<T>::try_mutate(id, |maybe_proposal| -> DispatchResult {
                let proposal = maybe_proposal.as_mut().ok_or(Error::<T>::NotFound)?;
                ensure!(proposal.state == ProposalState::Active, Error::<T>::InvalidState);
                ensure!(proposal.proposer == who, Error::<T>::NotProposer);
                proposal.state = ProposalState::Executed;
                T::Currency::transfer(&who, &proposal.proposer, proposal.amount, AllowDeath)?;
                TotalLocked::<T>::mutate(|total| *total += proposal.amount);
                Self::deposit_event(Event::ProposalExecuted { id, amount: proposal.amount });
                Ok(())
            })
        }

        #[pallet::weight(10_000)]
        pub fn cancel_proposal(origin: OriginFor<T>, id: u32) -> DispatchResult {
            ensure_none(origin)?;
            Proposals::<T>::try_mutate(id, |maybe_proposal| -> DispatchResult {
                let proposal = maybe_proposal.as_mut().ok_or(Error::<T>::NotFound)?;
                proposal.state = ProposalState::Cancelled;
                Self::deposit_event(Event::ProposalCancelled { id });
                Ok(())
            })
        }

        #[pallet::weight(10_000)]
        pub fn governance_action(origin: OriginFor<T>, id: u32) -> DispatchResult {
            T::GovernanceOrigin::ensure_origin(origin)?;
            T::Staking::bond(&who, amount)?;
            Ok(())
        }
    }

    #[pallet::error]
    pub enum Error<T> {
        NotFound,
        InvalidState,
        NotProposer,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            ProposalCount::<T>::get();
            Weight::zero()
        }

        fn on_finalize(_n: BlockNumberFor<T>) {
            ProposalCount::<T>::get();
        }

        fn on_runtime_upgrade() -> Weight {
            ProposalCount::<T>::mutate(|c| *c = 0);
            Weight::zero()
        }
    }

    #[pallet::inherent]
    impl<T: Config> ProvideInherent for Pallet<T> {
        fn create_inherent(data: &InherentData) -> Option<Self::Call> {
            Some(Call::submit_timestamp { now: data.timestamp })
        }
    }
}
