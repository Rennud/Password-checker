import requests
import hashlib
from db import delete_account, delete_data, search_data, save_data, save_credentials, check_username, verify_login


def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    respond = requests.get(url)
    if respond.status_code != 200:
        raise RuntimeError(f"Error fetching: {respond.status_code}, check the api and try it again")
    return respond


def get_password_leaks_count(hashes, hast_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hast_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail), sha1password


def user_registration():
    user_name = input("Choose username: ")
    if check_username(user_name):
        print("Username is already in use.")
    else:
        password = input("Choose password: ")
        sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        save_credentials(user_name, sha1password)
        print("Registration is complete!")


def user_login():
    while True:
        login_username = input("USERNAME: ")
        login_password = input("PASSWORD: ")
        sha1password = hashlib.sha1(login_password.encode("utf-8")).hexdigest().upper()
        if verify_login(login_username, sha1password):
            return login_username
        else:
            print("Wrong username or password.")
            continue


def main():
    while True:
        login_register = input("1 - Login, 2 - Registration,  3 - Delete account, 4 - QUIT: ")
        if login_register == "1":
            name = user_login()
            while True:
                options = input("1 - Check password, 2 - Search in DB, 3 - Delete saved data , 4 - QUIT ")
                if options == "1":
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
                elif options == "2":
                    password = input("Type password you want to check: ")
                    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
                    if search_data(name, sha1password):
                        print("This password matched with hash in db.")
                    else:
                        print("The password not matched with hash in db.")
                elif options == "3":
                    delete_data(name)
                    print("All data successfully deleted.")
                elif options == "4":
                    print("Good bye.")
                    break
                else:
                    print("INVALID OPTION")
        elif login_register == "2":
            user_registration()
            continue
        elif login_register == "3":
            username = input("USERNAME: ")
            password = input("PASSWORD: ")
            sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
            delete_data(username)
            delete_account(username, sha1password)
            print("Account no longer exists.")
        elif login_register == "4":
            exit()
        else:
            print("INVALID OPTION")


if __name__ == "__main__":
    main()