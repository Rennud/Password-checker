import requests
import hashlib
from db import delete_account, delete_data, search_data, save_data, save_credentials, verify_username, verify_credentials


# Through this API we can get all leaked passwords as hashes
def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char  # first five characters of our hashed password
    respond = requests.get(url)
    if respond.status_code != 200:
        raise RuntimeError(f"Error fetching: {respond.status_code}, check the api and try it again")
    return respond


# We compare our hashed password with the data we got.
# If there is a match we count how many times are password was leaked.
def get_password_leaks_count(hash_passwords, hast_to_check):
    hash_passwords = (line.split(":") for line in hash_passwords.text.splitlines())
    for h, count in hash_passwords:
        if h == hast_to_check:
            return count
    return 0


# Hash password - sha1.
def hash_password(password):
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


# For security reason we only send first 5 characters of our hashed password.
def pwned_api_check(password):
    hashed_password = hash_password(password)
    first5_char, tail = hashed_password[:5], hashed_password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail), hashed_password


def user_registration():
    user_name = input("Choose username: ")
    if verify_username(user_name):
        print("Username is already in use.")
    else:
        password = input("Choose password: ")
        hashed_password = hash_password(password)
        save_credentials(user_name, hashed_password)
        print("Registration is complete!")


def user_login():
    while True:
        login_username = input("USERNAME: ")
        login_password = input("PASSWORD: ")
        hashed_password = hash_password(login_password)
        if not verify_credentials(login_username, hashed_password):
            if not verify_username(login_username):
                print("Username don´t exist.")
            else:
                print("Wrong username or password.")
                continue
            continue
        return login_username


def main():
    # First pallet of options
    while True:
        first_pallet_of_options = input("1 - Login, 2 - Registration,  3 - Delete account, 4 - QUIT: ")
        if first_pallet_of_options == "1":
            name = user_login()
            # Second pallet of options
            while True:
                second_pallet_of_options = input("1 - Check password, 2 - Search in DB, 3 - Delete saved data , "
                                                 "4 - Logout ")
                if second_pallet_of_options == "1":
                    password = input("Type password you want to check: ")
                    count, hashed_password = pwned_api_check(password)
                    if count:
                        print(f"{password} was found {count} times. You should change your password.")
                    else:
                        print(f"{password} was NOT found.")
                    save_option = input("Do you want to save password as hash? y/n: ")
                    if save_option == "y":
                        save_data(name, hashed_password)
                        continue
                    else:
                        continue
                elif second_pallet_of_options == "2":
                    password = input("Type password you want to check: ")
                    hashed_password = hash_password(password)
                    if search_data(name, hashed_password):
                        print("This password matched with hash in db.")
                    else:
                        print("The password not matched with hash in db.")
                elif second_pallet_of_options == "3":
                    delete_data(name)
                    print("Successfully deleted.")
                elif second_pallet_of_options == "4":
                    print("Good bye.")
                    break
                else:
                    print("INVALID OPTION")
        elif first_pallet_of_options == "2":
            user_registration()
            continue
        elif first_pallet_of_options == "3":
            username = input("USERNAME: ")
            password = input("PASSWORD: ")
            hashed_password = hash_password(password)
            if not verify_username(username):
                print("Username don´t exist.")
            elif verify_credentials(username, hashed_password):
                delete_data(username)
                delete_account(username, hashed_password)
                print("Account no longer exists.")
            else:
                print("Invalid username or password.")

        elif first_pallet_of_options == "4":
            exit()
        else:
            print("INVALID OPTION")


if __name__ == "__main__":
    main()
