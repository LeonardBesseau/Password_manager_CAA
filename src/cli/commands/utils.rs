use crate::data::user::UserDataUnlocked;
use read_input::prelude::input;
use read_input::{InputBuild, InputConstraints};

pub fn select_password_entry(user_data: &UserDataUnlocked) -> Option<usize> {
    let entries = user_data.get_password_list();
    for (i, entry) in entries.iter().enumerate() {
        print!("{} - {}", i + 1, &entry.site);
        if entry.shared_by.is_some() {
            print!(" | Shared by {}", entry.shared_by.as_ref().unwrap());
        }
        println!();
    }
    loop {
        let selected = input::<usize>().repeat_msg("Please select a site to display its password or 0 to return to the previous screen\n"
        ).min(0).get();
        if selected == 0 {
            return None;
        } else if selected > entries.len() {
            println!(
                "The demanded site does not exists. Please stay in the range 0-{}",
                entries.len()
            );
        } else {
            return Some(selected - 1);
        }
    }
}
