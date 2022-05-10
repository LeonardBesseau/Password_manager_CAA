# CAA Lab 02

## Multi-user password manager
___
# Functionality
- Add password
- Recover a password
- Change master password
- Test password strength
- Generate password based on a charset
- Share a password with another user

# How to use
TODO
___
# Lab objectives
This program is a multi-user password manager realized for the Advanced Applied Cryptography (CAA) at HEIG-VD.
The goal is to implement a (somewhat) secure password manager and modellize its security.

### Password manager
Password managers are software used to manage the passwords of different websites/programs. They
are unlocked using a master password which is the only password the user has to remember. He will
use this password to login into the software.
Our password manager can be in two different states:
1. **Locked**: the state in which the password manager is before log-in.


2. **Unlocked**: once the user logged into the password manager and entered his master password, the
   password manager is in the unlocked state for that user. To recover passwords, the user does not
   have to type his master password anymore.

## Security requirements
### Locked mode
- One should not be able to recover any password (including the master password) without knowing
  the master password in this state.
- Bruteforcing the master password should be difficult even if some passwords of the database are
  known. Being able to bruteforce trivial passwords is ok (123456 is trivial. HouseWithHorse is not)
### Unlocked mode
- It should not be possible to extract the master password from the memory.
- Unaccessed passwords should not be in clear in the memory.

### Password sharing
A user should be able to share his password with another user of the software. For this, he
simply has to type (or select) an other username and a label and the password should be added (in a
secure way) in the other user’s account. Note that while sharing, the password should remain secure
and not leak or stay in clear somewhere.

## Functional requirements
The implementation must offer the following functionalities:
- A way to recover the password of a website. Displaying the password in the terminal is fine. Putting it directly in the clipboard is a plus.
- A way to add a new password in the database.
- A way to change the master password.
- A way to share a password with another user.

## Report requirements
A report containing the security model of the software, the reasoning for the primitives chosen and operations undertaken.