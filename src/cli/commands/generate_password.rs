use rand::Rng;
use rand_core::OsRng;
use read_input::prelude::input;
use read_input::{InputBuild, InputConstraints};
use secrecy::{ExposeSecret, SecretString};

fn generate_password(charset: &str, length: usize) -> SecretString {
    let mut output = String::with_capacity(length);
    let distr = rand::distributions::Uniform::new(0, charset.len());
    let chars: Vec<char> = charset.chars().collect();
    for _ in 0..length {
        output.push(*chars.get(OsRng.sample(distr)).unwrap());
    }
    SecretString::new(output)
}

pub fn menu() {
    println!("Password generator.");
    let number_charset = "0123456789";
    let letter_charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let special_charset = "!@#$%^&*";

    loop {
        let selected = input::<usize>()
            .repeat_msg(
                "Select one of the following \
        \n0 - Return to previous menu\
        \n1 - Only numbers\
        \n2 - Only letters (lower and upper case)\
        \n3 - Letters + numbers\
        \n4 - Letters + numbers + special chars (!@#$%^&*)\
        \n5 - Custom charset\n",
            )
            .min_max(0, 5)
            .get();
        let select_charset = match selected {
            0 => {
                return;
            }
            1 => String::from(number_charset),
            2 => String::from(letter_charset),
            3 => {
                let mut output = String::from(number_charset);
                output.push_str(letter_charset);
                output
            }
            4 => {
                let mut output = String::from(number_charset);
                output.push_str(letter_charset);
                output.push_str(special_charset);
                output
            }
            5 => {
                let mut output;
                loop {
                    output = input::<String>().msg("Please enter your charset:").get();
                    if !output.is_empty() {
                        break;
                    }
                }
                output
            }
            _ => panic!("This should not happen"),
        };
        let selected_size = input::<usize>()
            .repeat_msg("Select the size of the password (0 to exit, maximum 64): ")
            .min_max(0, 64)
            .get();
        println!(
            "Your password is {}",
            generate_password(select_charset.as_str(), selected_size).expose_secret()
        );
        break;
    }
}
