# Injection 3

The login page seems secure, but there's a new page: lookup_user.php.
While it's escaped, there are no quotes around $id, so we can use UNION.

We can find the number of columns needed by injection with "ORDER BY x", where we increase x until it returns an error.

From this, we get that there are 7 columns.

We then need to find the table prefix, so we use "0 UNION ALL SELECT 1,(SELECT table_name FROM information_schema.tables LIMIT x,1)" where we change x to get the tables. (could have used substring and ascii to filter out the useless tables, but felt lazy) The 0 is an invalid user id so we get 1 row at the end.

Looking at the 40th table, we get the table name "super_secret_users".
We then use "0 UNION ALL select 1,username,1,password,1,1,1 from super_secret_users LIMIT 1--" to get the username and password required.
After logging in with these credentials, we get the flag.
