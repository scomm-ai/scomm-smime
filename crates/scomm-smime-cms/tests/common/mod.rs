//! Interop results as a matrix of expected outcomes.
//!
//! A case either works or is a known gap named after its audit finding
//! (`docs/audits/e2ee-ecc-pqc-audit-2026-11-06.md` in secMail0). A gap that starts
//! working fails the run too, so the matrix stays true.

#[derive(Clone, Copy)]
pub enum Expect {
    Works,
    Gap(&'static str),
}

#[derive(Default)]
pub struct Matrix {
    rows: Vec<String>,
    mismatches: Vec<String>,
}

impl Matrix {
    pub fn case(&mut self, name: &str, expect: Expect, outcome: Result<(), String>) {
        let detail = outcome.as_ref().err().cloned().unwrap_or_default();
        match (expect, outcome.is_ok()) {
            (Expect::Works, true) => self.rows.push(format!("ok    {name}")),
            (Expect::Gap(id), false) => self.rows.push(format!("gap   {name} [{id}]: {detail}")),
            (Expect::Works, false) => {
                self.rows.push(format!("FAIL  {name}: {detail}"));
                self.mismatches.push(format!("{name} should work: {detail}"));
            }
            (Expect::Gap(id), true) => {
                self.rows.push(format!("FIXED {name} [{id}]"));
                self.mismatches
                    .push(format!("{name} now works, so remove gap {id}"));
            }
        }
    }

    pub fn finish(self, title: &str) {
        println!("\n== {title}\n{}", self.rows.join("\n"));
        assert!(self.mismatches.is_empty(), "{}", self.mismatches.join("\n"));
    }
}
