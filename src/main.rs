//Look at lib.rs for small description.

use finite_state_machine::Automaton;

fn main() {
    println!("Hello, Automaton!");

    let automaton1 = Automaton::new("abc").unwrap();
    assert!(automaton1.matches("abc"));
    assert!(!automaton1.matches("ab"));
    assert!(!automaton1.matches("abcd"));
    assert!(!automaton1.matches("bc"));
    assert!(!automaton1.matches("x"));
    assert!(!automaton1.matches(""));

    let automaton2 = Automaton::new("").unwrap();
    assert!(automaton2.matches(""));
    assert!(!automaton2.matches("xyz"));

    let automaton3 = Automaton::new("567");
    let err_string = match automaton3 {
        Ok(_) => "something went wrong".to_string(),
        Err(s) => s,
    };
    assert_eq!(err_string, "Wrong character: 5");
}
