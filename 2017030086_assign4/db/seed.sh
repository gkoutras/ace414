#!/bin/bash

rm -rf database.db
rm -rf mock_database.db

sqlite3 database.db < db_init.sql
sqlite3 mock_database.db < db_init_mock.sql

python3 seed_db.py
