//! Preliminary fail-closed policy matching; not an execution gateway.
//!
//! Upstream describes organization rules taking precedence over personal rules,
//! and `*` matching any text. Exact tie-breaking among overlapping rules and
//! upstream safety layers remain unverified. Therefore this module never grants
//! execution: it can only deny, ask for approval, or hand an action off.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behaviour { Allow, PreApproved, Ask, HandOff }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision { Deny, Ask, HandOff }
#[derive(Debug)]
pub struct Action<'a> { pub bot_id: &'a str, pub tool_ref: &'a str, pub effect: &'a str, pub scope: &'a str }
#[derive(Debug)]
pub struct Rule<'a> { pub bot_id: &'a str, pub tool_ref: &'a str, pub effect: &'a str, pub scope: &'a str, pub behaviour: Behaviour }

/// Matches a trimmed, bounded wildcard pattern over Unicode characters. `*`
/// is the only metacharacter. Bad or oversized data never matches.
fn matches_pattern(pattern: &str, value: &str) -> bool {
    let p=pattern.trim();
    if p.is_empty() || p.chars().count()>300 || p.contains('\0') || value.is_empty() || value.len()>4096 || value.contains('\0') { return false; }
    let p:Vec<char>=p.chars().collect();let s:Vec<char>=value.chars().collect();
    let (mut i,mut j,mut star,mut restart)=(0,0,None,0);
    while j<s.len() {
        if i<p.len() && p[i]==s[j] {i+=1;j+=1;}
        else if i<p.len() && p[i]=='*' {star=Some(i);i+=1;restart=j;}
        else if let Some(k)=star {restart+=1;j=restart;i=k+1;}
        else {return false;}
    }
    while i<p.len()&&p[i]=='*' {i+=1;}
    i==p.len()
}
fn matches(rule:&Rule<'_>,action:&Action<'_>)->bool {
    matches_pattern(rule.bot_id,action.bot_id)&&matches_pattern(rule.tool_ref,action.tool_ref)&&matches_pattern(rule.effect,action.effect)&&matches_pattern(rule.scope,action.scope)
}

/// Conservatively evaluate a bounded rule set. Organization rules come first.
/// Conflicting matches deny because upstream overlap ordering is not yet known.
/// Even an allow rule denies until grants, identity, approval, audit and the
/// actual action executor are integrated in one fail-closed choke point.
pub fn decide(action:&Action<'_>, organization:&[Rule<'_>], personal:&[Rule<'_>])->Decision {
    if organization.len()>512 || personal.len()>512 {return Decision::Deny;}
    let mut selected=None;
    for rules in [organization,personal] {
        for rule in rules.iter().filter(|r|matches(r,action)) {
            if selected.is_some_and(|v|v!=rule.behaviour) {return Decision::Deny;}
            selected=Some(rule.behaviour);
        }
        if selected.is_some(){break;}
    }
    match selected {Some(Behaviour::Ask)=>Decision::Ask,Some(Behaviour::HandOff)=>Decision::HandOff,_=>Decision::Deny}
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rule<'a>(tool:&'a str,behaviour:Behaviour)->Rule<'a>{Rule{bot_id:"*",tool_ref:tool,effect:"*",scope:"*",behaviour}}
    #[test] fn wildcard_matches_without_regex_or_path_escape_assumptions(){assert!(matches_pattern("mcp/*/read","mcp/ń/read"));assert!(!matches_pattern("mcp/*/read","mcp/a/write"));assert!(!matches_pattern("*",""));assert!(!matches_pattern("*\0","x"));}
    #[test] fn never_grants_execution_and_organization_has_priority(){let a=Action{bot_id:"b",tool_ref:"mcp/mail/read",effect:"read",scope:"inbox"};assert_eq!(decide(&a,&[],&[]),Decision::Deny);assert_eq!(decide(&a,&[rule("*",Behaviour::Allow)],&[]),Decision::Deny);assert_eq!(decide(&a,&[rule("*",Behaviour::Ask)],&[rule("*",Behaviour::HandOff)]),Decision::Ask);assert_eq!(decide(&a,&[],&[rule("*",Behaviour::PreApproved)]),Decision::Deny);assert_eq!(decide(&a,&[rule("*",Behaviour::Ask),rule("*",Behaviour::HandOff)],&[]),Decision::Deny);}
}
