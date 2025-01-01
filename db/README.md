# db

I decided to separate the [database structure definition script](./init.sql) from the code because I want to demonstrate
that this one database can be used with multiple types of backend services.

```mermaid
erDiagram
    sa_user ||--o{ sa_user_authority: has
    sa_authority ||--o{ sa_user_authority: belongs
    sa_user {
        bigint id
        varchar(255) email
        varchar(255) password
        varchar(255) first_name
        varchar(255) last_name
        bool confirmed
        bool enabled
    }
    sa_authority {
        bigint id
        varchar(255) authority
    }
    sa_user_authority {
        bigint user_id
        bigint authority_id
    }
```
