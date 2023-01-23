import sqlite3

# seed the databases


def seed_db(cur: sqlite3.Cursor):
    for i in range(100):
        cur.execute(
            f"INSERT INTO items (name, category, price) VALUES ('item{i}', 'Music', 123)"
        )


# seed database.db

con = sqlite3.connect("./database.db")
seed_db(con.cursor())
con.commit()
con.close()


# seed mock database
con = sqlite3.connect("./mock_database.db")
seed_db(con.cursor())
con.commit()
con.close()
