/*
 * Realization of Finite State Automaton that accepts
 * string in constructor (allows lowercase latin alfabet, '.', '(', ')' and '*')
 * and then works on strings checking if they match the defined language or not.
 * Constructor strings examples: "abc", "a.c", "a(bc)*d" etc.
 */

use std::collections::BTreeSet;
use std::collections::HashMap;

#[derive(Debug)]
struct DFAState {
    nfa_states: BTreeSet<usize>,
    nfa_state_rules: HashMap<char, BTreeSet<usize>>,
    state_rules: HashMap<char, usize>,
    is_final: bool,
}

#[derive(Debug)]
struct NFAState {
    state_rules: HashMap<char, BTreeSet<usize>>,
    is_final: bool,
}

pub struct Automaton {
    zero_dfa_state_index: usize,
    dfa_states: Vec<DFAState>,
}

fn get_rules(states: &BTreeSet<usize>, nfa_states: &[NFAState]) -> HashMap<char, BTreeSet<usize>> {
    let mut result = HashMap::<char, BTreeSet<usize>>::new();
    for state_index in states {
        for (character, indices) in &nfa_states.get(*state_index).unwrap().state_rules {
            let state_indices = result.entry(*character).or_default();
            for i in indices {
                state_indices.insert(*i);
            }
        }
    }
    result
}

impl Automaton {
    pub fn new(regex: &str) -> Result<Automaton, String> {
        let mut chars = regex.chars();
        let mut nfa_states = vec![NFAState {
            is_final: false,
            state_rules: HashMap::new(),
        }];
        let mut current_state_index = 0;

        let mut cycle_start_points = Vec::<usize>::new();

        //parsing regex
        while let Some(c) = chars.next() {
            if c == '(' {
                cycle_start_points.push(current_state_index);
            } else if c == ')' {
                let next_c = chars.next();
                if let Some(next_c) = next_c {
                    if next_c == '*' {
                        if let Some(prev_cycle_start) = cycle_start_points.pop() {
                            let states = nfa_states
                                .get_mut(prev_cycle_start)
                                .unwrap()
                                .state_rules
                                .entry('0')
                                .or_insert(BTreeSet::new());
                            states.insert(current_state_index);

                            nfa_states
                                .get_mut(current_state_index)
                                .unwrap()
                                .state_rules
                                .insert('0', BTreeSet::from([prev_cycle_start]));
                        } else {
                            return Err(
                                "Regex has wrong structure, '(' missing somethere.".to_string()
                            );
                        }
                    } else {
                        return Err(format!(
                            "Regex has unexpected symbol after ')', '*' expected, got: {}",
                            next_c
                        ));
                    }
                } else {
                    return Err("Regex ended unexpectedly, '*' expected.".to_string());
                }
            } else if c.is_ascii_lowercase() || c == '.' {
                nfa_states.push(NFAState {
                    is_final: false,
                    state_rules: HashMap::new(),
                });
                current_state_index = nfa_states.len() - 1;

                nfa_states
                    .get_mut(current_state_index - 1)
                    .unwrap()
                    .state_rules
                    .insert(c, BTreeSet::from([current_state_index]));
            } else {
                return Err(format!("Wrong character: {}", c));
            }
        }
        nfa_states.get_mut(current_state_index).unwrap().is_final = true;

        //transforming NFA to DFA

        //getting epsilon rules
        let mut zero_rules = HashMap::<usize, BTreeSet<usize>>::new();
        for index in 0..nfa_states.len() {
            let nfa_state = nfa_states.get(index).unwrap();
            if let Some(indices) = nfa_state.state_rules.get(&'0') {
                let rule = zero_rules.entry(index).or_insert(BTreeSet::new());
                for next_index in indices {
                    rule.insert(*next_index);
                }
            }
        }

        //getting epsilon closures for all nfa states
        let mut epsilon_closures = HashMap::new();
        for index in 0..nfa_states.len() {
            let mut epsilon_closure = BTreeSet::from([index]);
            loop {
                let mut new_indices = BTreeSet::new();

                for closure_index in &epsilon_closure {
                    if let Some(indices) = zero_rules.get(closure_index) {
                        for new_closure_index in indices {
                            if !epsilon_closure.contains(new_closure_index) {
                                new_indices.insert(*new_closure_index);
                            }
                        }
                    }
                }

                if new_indices.is_empty() {
                    break;
                } else {
                    for index in new_indices {
                        epsilon_closure.insert(index);
                    }
                }
            }
            epsilon_closures.insert(index, epsilon_closure);
        }

        //getting zero state
        let mut dfa_states = vec![];
        let mut zero_nfa_states = BTreeSet::new();
        for num in epsilon_closures.get(&0).unwrap() {
            zero_nfa_states.insert(*num);
        }
        let zero_nfa_state_rules = get_rules(&zero_nfa_states, &nfa_states);

        dfa_states.push(DFAState {
            nfa_states: zero_nfa_states.clone(),
            nfa_state_rules: zero_nfa_state_rules,
            state_rules: HashMap::new(),
            is_final: false,
        });
        let mut dfa_states_to_process_indices = vec![0];

        //processing all ways from existing states
        let mut helper_hashmap_to_find_dfa_states_faster = HashMap::new();
        helper_hashmap_to_find_dfa_states_faster.insert(zero_nfa_states, 0);

        while let Some(dfa_state_to_process_index) = dfa_states_to_process_indices.pop() {
            let mut this_state_rules = HashMap::new();
            let mut new_dfa_states = vec![];
            for (character, next_states_indices) in &dfa_states
                .get(dfa_state_to_process_index)
                .unwrap()
                .nfa_state_rules
            {
                let mut next_states_with_epsilon_closures_indices = BTreeSet::new();
                for next_state_index in next_states_indices {
                    next_states_with_epsilon_closures_indices.insert(*next_state_index);
                    for epsilon_closure_index in epsilon_closures.get(next_state_index).unwrap() {
                        next_states_with_epsilon_closures_indices.insert(*epsilon_closure_index);
                    }
                }
                this_state_rules.insert(*character, next_states_with_epsilon_closures_indices);

                //if the dfa state is new, add it to list
                if !helper_hashmap_to_find_dfa_states_faster
                    .contains_key(this_state_rules.get(character).unwrap())
                {
                    new_dfa_states.push(DFAState {
                        nfa_states: this_state_rules.get(character).unwrap().clone(),
                        nfa_state_rules: get_rules(
                            this_state_rules.get(character).unwrap(),
                            &nfa_states,
                        ),
                        state_rules: HashMap::new(),
                        is_final: false,
                    });
                    dfa_states_to_process_indices.push(dfa_states.len() + new_dfa_states.len() - 1);
                }
            }
            for new_dfa_state in new_dfa_states {
                helper_hashmap_to_find_dfa_states_faster
                    .insert(new_dfa_state.nfa_states.clone(), dfa_states.len());
                dfa_states.push(new_dfa_state);
            }

            dfa_states
                .get_mut(dfa_state_to_process_index)
                .unwrap()
                .nfa_state_rules = this_state_rules;
        }

        //converting nfa_state_rules to dfa normal state_rules
        for dfa_index in 0..dfa_states.len() {
            let nfa_state_rules = &dfa_states.get(dfa_index).unwrap().nfa_state_rules;
            let mut state_rules = HashMap::new();
            for (character, states_indices) in nfa_state_rules {
                if let Some(pos) = dfa_states
                    .iter()
                    .position(|dfa_state| dfa_state.nfa_states == *states_indices)
                {
                    state_rules.insert(*character, pos);
                } else {
                    return Err("That really shouldn't have happened.".to_string());
                }
            }
            dfa_states.get_mut(dfa_index).unwrap().state_rules = state_rules;
        }

        //marking final states
        for dfa_index in 0..dfa_states.len() {
            let nfa_indices = &dfa_states.get(dfa_index).unwrap().nfa_states;
            for nfa_index in nfa_indices {
                if nfa_states.get(*nfa_index).unwrap().is_final {
                    dfa_states.get_mut(dfa_index).unwrap().is_final = true;
                    break;
                }
            }
        }

        Ok(Automaton {
            zero_dfa_state_index: 0,
            dfa_states,
        })
    }

    pub fn matches(&self, input: &str) -> bool {
        let mut input_chars = input.chars();
        let mut current_state_index = self.zero_dfa_state_index;
        loop {
            let input_ch = input_chars.next();
            if let Some(input_ch) = input_ch {
                let state_rules = &self
                    .dfa_states
                    .get(current_state_index)
                    .unwrap()
                    .state_rules;
                if let Some(next_state_index) = state_rules.get(&input_ch) {
                    current_state_index = *next_state_index;
                } else if let Some(next_state_index) = state_rules.get(&'.') {
                    current_state_index = *next_state_index;
                } else {
                    return false;
                }
            } else {
                return self.dfa_states.get(current_state_index).unwrap().is_final;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Automaton;

    #[test]
    fn empty_regex() {
        let automaton2 = Automaton::new("").unwrap();
        assert!(automaton2.matches(""));
        assert!(!automaton2.matches("xyz"));
    }

    #[test]
    fn simple_regex() {
        let automaton1 = Automaton::new("abc").unwrap();
        assert!(automaton1.matches("abc"));
        assert!(!automaton1.matches("ab"));
        assert!(!automaton1.matches("abcd"));
        assert!(!automaton1.matches("bc"));
        assert!(!automaton1.matches("x"));
        assert!(!automaton1.matches(""));
    }

    #[test]
    fn dot_regex() {
        let automaton4 = Automaton::new("ab.").unwrap();
        assert!(automaton4.matches("abc"));
        assert!(!automaton4.matches("ab"));
        assert!(!automaton4.matches("abcd"));
        assert!(automaton4.matches("abt"));

        let automaton5 = Automaton::new("a.c").unwrap();
        assert!(automaton5.matches("abc"));
        assert!(!automaton5.matches("ab"));
        assert!(!automaton5.matches("abcd"));
        assert!(automaton5.matches("axc"));
    }

    #[test]
    fn cycle_regex() {
        let automaton4 = Automaton::new("(ab)*").unwrap();
        assert!(automaton4.matches("ab"));
        assert!(!automaton4.matches("abc"));
        assert!(!automaton4.matches("cab"));
        assert!(automaton4.matches("abab"));
        assert!(automaton4.matches(""));

        let automaton5 = Automaton::new("a(bc)*d").unwrap();
        assert!(automaton5.matches("abcd"));
        assert!(!automaton5.matches("ab"));
        assert!(!automaton5.matches("abcde"));
        assert!(automaton5.matches("abcbcbcd"));
        
        let automaton5_1 = Automaton::new("a((bc)*)*d").unwrap();
        assert!(automaton5_1.matches("abcd"));
        assert!(!automaton5_1.matches("ab"));
        assert!(!automaton5_1.matches("abcde"));
        assert!(automaton5_1.matches("abcbcbcd"));
        
        let automaton5_2 = Automaton::new("a((bc)*c)*d").unwrap();
        assert!(automaton5_2.matches("abccd"));
        assert!(!automaton5_2.matches("ab"));
        assert!(!automaton5_2.matches("abcde"));
        assert!(automaton5_2.matches("abcbcbcd"));
        assert!(automaton5_2.matches("abccbccd"));
    }

    #[test]
    fn many_cycles_regex() {
        let automaton4 = Automaton::new("(ab)*(cd)*").unwrap();
        assert!(automaton4.matches("ab"));
        assert!(!automaton4.matches("abc"));
        assert!(!automaton4.matches("cab"));
        assert!(automaton4.matches("abab"));
        assert!(automaton4.matches("abcd"));
        assert!(automaton4.matches("cd"));
        assert!(automaton4.matches("ababcd"));
        assert!(automaton4.matches("ababcdcd"));
        assert!(automaton4.matches(""));

        let automaton5 = Automaton::new("(a(bc)*d)*").unwrap();
        assert!(automaton5.matches("abcd"));
        assert!(!automaton5.matches("ab"));
        assert!(!automaton5.matches("abcde"));
        assert!(automaton5.matches("abcbcbcd"));
        assert!(automaton5.matches("abcdabcd"));
        assert!(automaton5.matches("abcbcdabcd"));
    }

    #[test]
    fn mixed_regex() {
        let automaton4 = Automaton::new(".(a.)*c").unwrap();
        assert!(automaton4.matches("aabc"));
        assert!(!automaton4.matches("abc"));
        assert!(!automaton4.matches("cab"));
        assert!(automaton4.matches("aabacc"));
        assert!(automaton4.matches("cc"));

        let automaton5 = Automaton::new("a(..)*d").unwrap();
        assert!(automaton5.matches("abcd"));
        assert!(!automaton5.matches("ab"));
        assert!(!automaton5.matches("abcde"));
        assert!(automaton5.matches("abcbcbad"));
    }

    #[test]
    fn wrong_regex() {
        let automaton3 = Automaton::new("567");
        let err_string = match automaton3 {
            Ok(_) => "something went wrong".to_string(),
            Err(s) => s,
        };
        assert_eq!(err_string, "Wrong character: 5");

        let automaton6 = Automaton::new("abc)*");
        let err_string = match automaton6 {
            Ok(_) => "something went wrong".to_string(),
            Err(s) => s,
        };
        assert_eq!(
            err_string,
            "Regex has wrong structure, '(' missing somethere."
        );

        let automaton7 = Automaton::new("(abc)a");
        let err_string = match automaton7 {
            Ok(_) => "something went wrong".to_string(),
            Err(s) => s,
        };
        assert_eq!(
            err_string,
            "Regex has unexpected symbol after ')', '*' expected, got: a"
        );

        let automaton8 = Automaton::new("(abc)");
        let err_string = match automaton8 {
            Ok(_) => "something went wrong".to_string(),
            Err(s) => s,
        };
        assert_eq!(err_string, "Regex ended unexpectedly, '*' expected.");
    }
}
