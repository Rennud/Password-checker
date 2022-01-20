import sqlite3


# Delete account with credentials and saved hashes.
def delete_account(name, password):
    con = sqlite3.connect('db.db')
    cur = con.cursor()

    cur.execute('DELETE FROM users WHERE username =? AND password =?', (name, password))

    con.commit()
    con.close()


# Delete saved hashes.
def delete_data(name):
    con = sqlite3.connect('db.db')
    cur = con.cursor()

    cur.execute('DELETE FROM user_hash WHERE username =?', (name,))

    con.commit()
    con.close()


# Search if you already check that password.
def search_data(name, password):
    con = sqlite3.connect('db.db')
    cur = con.cursor()

    if cur.execute('SELECT EXISTS(SELECT * FROM user_hash WHERE username =? AND hash =?)',
                   (name, password)).fetchone() == (1,):
        con.commit()
        con.close()
        return True

    else:
        con.commit()
        con.close()
        return False


# Save hash of the password you searched for.
def save_data(name, password):
    con = sqlite3.connect('db.db')
    cur = con.cursor()

    cur.execute('INSERT INTO user_hash VALUES(?,?)', (name, password))

    con.commit()
    con.close()


# Save user name and password
def save_credentials(name, password):
    con = sqlite3.connect('db.db')
    cur = con.cursor()

    cur.execute('INSERT INTO users VALUES(?,?)', (name, password))

    con.commit()
    con.close()


# Verify if username is in db.
def verify_username(name):
    con = sqlite3.connect('db.db')
    cur = con.cursor()

    if cur.execute('SELECT EXISTS(SELECT * FROM users WHERE username =?)', (name,)).fetchone() == (1,):
        con.commit()
        con.close()
        return True
    else:
        con.commit()
        con.close()
        return False


# Verify if username and users passwords are correct
def verify_credentials(name, password):
    con = sqlite3.connect('db.db')
    cur = con.cursor()

    if cur.execute('SELECT EXISTS(SELECT * FROM users WHERE username =? AND password =?)',
                   (name, password)).fetchone() == (1,):
        con.commit()
        con.close()
        return True

    else:
        con.commit()
        con.close()
        return False
