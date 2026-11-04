\getenv app_db_name APP_DB_NAME
\getenv app_db_user APP_DB_USER
\getenv app_db_password APP_DB_PASSWORD

CREATE ROLE :"app_db_user"
    WITH LOGIN PASSWORD :'app_db_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;

REVOKE CONNECT ON DATABASE :"app_db_name" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"app_db_name" TO :"app_db_user";
