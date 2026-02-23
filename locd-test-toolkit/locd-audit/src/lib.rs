//! Security audit tools for Loc'd Protocol
//!
//! This crate provides:
//! - Timing attack detection via statistical analysis
//! - Fuzzing infrastructure for protocol components
//! - Known vulnerability scanning
//!
//! # Usage
//!
//! ```bash
//! # Scan for known vulnerabilities
//! locd-audit scan
//!
//! # Run timing analysis
//! locd-audit timing --samples 10000
//!
//! # Run full audit
//! locd-audit full
//! ```

pub mod timing;
pub mod vulns;

#[cfg(test)]
mod tests {
    #[test]
    fn test_library_imports() {
        // Verify all dependencies are accessible
        let _ = locd_core::IdentityDomain::new("test.example.com");
    }
}
