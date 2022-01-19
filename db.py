import sqlite3


def delete_account(name, password):
    con = sqlite3.connect('db.db')
    cur = con.cursor()

    cur.execute('DELETE FROM users WHERE username =? AND password =?', (name, password))

    con.commit()
    con.close()


def delete_data(name):
    con = sqlite3.connect('db.db')
    cur = con.cursor()

    cur.execute('DELETE FROM user_hash WHERE username =?', name)

    con.commit()
    con.close()


def search_data(name, password):
    con = sqlite3.connect('db.db')
    cur = con.cursor()

    if cur.execute('SELECT EXISTS(SELECT * FROM user_hash WHERE username =? AND hash =?)', (name, password)).fetchone() == (1,):
        con.commit()
        con.close()
        return True

    else:
        con.commit()
        con.close()
        return False


def save_data(name, password):
    con = sqlite3.connect('db.db')
    cur = con.cursor()

    cur.execute("INSERT INTO user_hash VALUES(?,?)", (name, password))

    con.commit()
    con.close()


def save_credentials(name, password):
    con = sqlite3.connect('db.db')
    cur = con.cursor()

    cur.execute("INSERT INTO users VALUES(?,?)", (name, password))

    con.commit()
    con.close()


def check_username(name):
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


def verify_login(name, password):
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
