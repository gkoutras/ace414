# ACE414 Assingment 4

In this assignment, a log-in page, CTF-style, application is given. The goal is to use the SQL Injection vulnerabilities present withing the application’s login to login as “superadmin”!

---

1. In order to exploit the present vulnerability in the "login" field and get access to the database without having to find a password for the user, an insertion must be made so the code at the server will create a valid SQL statement. This insertion is `' OR TRUE --`, which creates `SELECT * FROM users WHERE username = 'user' AND password = '' OR TRUE --'` as the SQL statement that can bypass the "login", since the `OR TURE` is always true. After that, access is permitted to the "dashboard".

2. In order to exploit the present vulnerability in the "dashboard" field and get access to the "user" table, instead of the "items" table, just like before, a new insertion must be made so the code at the server will create a valid SQL statement. This insertion is `' UNION SELECT * FROM users --`, which creates `SELECT name,category,price FROM items WHERE name = '' UNION SELECT * FROM users --'` as the SQL statement that can retrieve all information from the "user" table, and none from the "item" table. Thanks to this line of code: `results = res.fetchall()[0]` in app.py, the item that is returned from the "user" table is the superadmin item, containing the admin password: <ins>sup3r4dm1nP@5sw0rd</ins>, which can now be masterfully copied!

3. Logging in to the "admin" field is now possible and the trophy is: **TUC{SQLi_1s_4w3s0m3_NGL_4nd_th3_sky_1s_blu3}**!

---

In conlcusion, the inputs used to bypass the fields are the following:
- "Login" field: `' OR TRUE --`
- "Search" field: `' UNION SELECT * FROM users --`
