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
Clone the repository and compile the program. You need write-and read-permission for the current folder.
Here is a quick demo of the program:
```
Welcome to the very secure password manager !
Please select one of the following to continue
0 - Exit
1 - Login
2 - Create new account
1
Please enter your username (Enter with no input to return to previous screen): exemple
Please enter your password (Enter with no input to return to previous screen): SuperSecretPassword
Welcome exemple !
Please select one of the following to continue
0 - Exit
1 - Add password
2 - Show password
3 - Share password
4 - Verify password strength
5 - Generate password
6 - Change master password
2
1 - my super site
2 - google
Please select a site to display its password or 0 to return to the previous screen
1
Site: my super site
Username: username
Password: abcdefghijklmnop
Please select one of the following to continue
0 - Exit
1 - Add password
2 - Show password
3 - Share password
4 - Verify password strength
5 - Generate password
6 - Change master password
3
1 - my super site
2 - google
Please select a site to display its password or 0 to return to the previous screen
2
Enter the username to share the password with (Enter with no input to return to previous screen): do_not_exist
The selected user does not exist !
Enter the username to share the password with (Enter with no input to return to previous screen):Another exemple
Password shared !!! 
```
```
Please select one of the following to continue
0 - Exit
1 - Login
2 - Create new account
1
Please enter your username (Enter with no input to return to previous screen): Another exemple
Please enter your password (Enter with no input to return to previous screen): This Is a secret
Welcome Another exemple !
Please select one of the following to continue
0 - Exit
1 - Add password
2 - Show password
3 - Share password
4 - Verify password strength
5 - Generate password
6 - Change master password
2
1 - google | Shared by exemple
2 - test
3 - a
Please select a site to display its password or 0 to return to the previous screen
```
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
simply has to type (or select) another username and a label and the password should be added (in a
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