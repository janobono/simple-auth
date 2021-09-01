insert into simple_auth_user(id, username, password, enabled)
values (nextval('sq_simple_auth_user'), 'trevor.ochmonek.dev',
        '$2a$10$DiZet0o1I9E1TogKsnTosuWr.jMuvFBnlknrLIcPhOebW0nXPyeXa', true);

insert into simple_auth_user_attribute(user_id, key, value)
values (currval('sq_simple_auth_user'), 'email', 'trevor.ochmonek@melmac.com');
insert into simple_auth_user_attribute(user_id, key, value)
values (currval('sq_simple_auth_user'), 'given_name', 'Trevor');
insert into simple_auth_user_attribute(user_id, key, value)
values (currval('sq_simple_auth_user'), 'family_name', 'Ochmonek');
insert into simple_auth_user_attribute(user_id, key, value)
values (currval('sq_simple_auth_user'), 'hotel_code', 'simple-123');

insert into simple_auth_user_authority(user_id, authority_id)
values (currval('sq_simple_auth_user'), 1);
insert into simple_auth_user_authority(user_id, authority_id)
values (currval('sq_simple_auth_user'), 2);
