// SM3 算法封装
// 封装 libsmx 的 SM3，提供 init/update/final 状态机接口

use libsmx::sm3::{Sm3Hasher, hmac_sm3};

/// SM3 哈希状态机（用于 HashInit/HashUpdate/HashFinal）
/// Reason: SDF 接口是流式哈希，需要维护中间状态
#[derive(Clone)]
pub struct Sm3State {
    hasher: Sm3Hasher,
}

// Reason: Sm3Hasher 未实现 Debug，手动实现以满足上层 HashCtx 的 derive(Debug) 需求
impl std::fmt::Debug for Sm3State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sm3State").finish_non_exhaustive()
    }
}

impl Sm3State {
    pub fn new() -> Self {
        Self { hasher: Sm3Hasher::new() }
    }

    /// 追加数据
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// 完成计算，返回32字节摘要
    /// Reason: finalize 消耗 self，通过 clone 保持原 hasher 不变
    pub fn finalize(&self) -> [u8; 32] {
        self.hasher.clone().finalize()
    }

    /// 重置状态
    pub fn reset(&mut self) {
        self.hasher.reset();
    }
}

impl Default for Sm3State {
    fn default() -> Self {
        Self::new()
    }
}

/// 直接计算 SM3 哈希（一次性）
pub fn sm3_digest(data: &[u8]) -> [u8; 32] {
    Sm3Hasher::digest(data)
}

/// HMAC-SM3
pub fn hmac_sm3_digest(key: &[u8], data: &[u8]) -> [u8; 32] {
    hmac_sm3(key, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm3_empty() {
        // SM3("") = 1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B
        let result = sm3_digest(b"");
        let expected = hex::decode("1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B").unwrap();
        assert_eq!(result.to_vec(), expected);
    }

    #[test]
    fn test_sm3_state_machine() {
        let full = sm3_digest(b"hello world");
        let mut state = Sm3State::new();
        state.update(b"hello ");
        state.update(b"world");
        let chunked = state.finalize();
        assert_eq!(full, chunked);
    }
}
