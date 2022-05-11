use crate::input::ask_for_password;
use secrecy::ExposeSecret;
use zxcvbn::zxcvbn;

pub fn verify_password_strength() {
    println!("Welcome to the password tester !");
    let password = match ask_for_password() {
        None => {
            return;
        }
        Some(s) => s,
    };

    let entropy = zxcvbn(password.expose_secret(), &[]).unwrap();
    let score_description = match entropy.score() {
        0 | 1 => "catastrophic",
        2 => "bad",
        3 => "average",
        4 => "good",
        _ => panic!("Should not happen"),
    };
    println!(
        "Score {}/4. Your password is {}. It would take {} guess in average",
        entropy.score(),
        score_description,
        entropy.guesses()
    );
    if (&entropy).score() < 2 && (&entropy).feedback().is_some() {
        let feedback = (entropy.feedback()).as_ref().unwrap();
        if feedback.warning().is_some() {
            println!("CAUTION!!! {}", feedback.warning().unwrap());
        }
        if !feedback.suggestions().is_empty() {
            println!("Here is a few suggestion to improve your password :");
            for i in feedback.suggestions() {
                println!("{}", i);
            }
        }
    }
}
