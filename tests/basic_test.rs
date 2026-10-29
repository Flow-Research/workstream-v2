#[cfg(test)]
mod tests {
    use flowstream_core::types::*;
    use flowstream_core::hash::{Hash, H256};
    use flowstream_state::State;
    use flowstream_stf::StateTransitionFunction;
    use flowstream_tx::TxBuilder;
    
    #[test]
    fn test_state_creation() {
        let state = State::new();
        let root = state.root();
        assert_eq!(root.version, 1);
        assert_eq!(root.smt_root, H256::ZERO);
        assert_eq!(root.mmr_root, H256::ZERO);
    }
    
    #[test]
    fn test_hash() {
        let data = b"hello world";
        let h = Hash::sha256(data);
        assert_eq!(h.as_bytes().len(), 32);
    }
    
    #[test]
    fn test_tx_builder() {
        let account = H256::from_bytes([1u8; 32]);
        let tx = TxBuilder::new()
            .chain_id(1)
            .account(account)
            .nonce(0, 1)
            .add_action(ActionType::ActorRegister, vec![1, 2, 3])
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1000,
            })
            .build()
            .unwrap();
        
        assert_eq!(tx.chain_id, 1);
        assert_eq!(tx.actions.len(), 1);
        assert_eq!(tx.actions[0].action_type, ActionType::ActorRegister);
    }
    
    #[test]
    fn test_stf_basic() {
        let mut state = State::new();
        let stf = StateTransitionFunction::new();
        
        let account = H256::from_bytes([1u8; 32]);
        let tx = TxBuilder::new()
            .chain_id(1)
            .account(account)
            .nonce(0, 1)
            .add_action(ActionType::ActorRegister, vec![])
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1000,
            })
            .build()
            .unwrap();
        
        let result = stf.execute_tx(&mut state, &tx);
        assert!(result.is_ok());
    }
}
