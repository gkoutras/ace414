CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(30) NOT NULL,
    password VARCHAR(30) NOT NULL
);
CREATE TABLE items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(30) NOT NULL,
    category VARCHAR(30) NOT NULL,
    price INTEGER NOT NULL
);
INSERT INTO users (username, password)
VALUES ('superadmin', 'superadmin');
INSERT INTO users (username, password)
VALUES ('user', 'user');