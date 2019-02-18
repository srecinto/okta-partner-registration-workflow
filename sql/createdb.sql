

create table partner_approval_queue (
    okta_group_id varchar(100),
    okta_user_id varchar(100),
    primary key (okta_group_id, okta_user_id)
);

create table admin_approval_queue (
    okta_group_id varchar(100),
    okta_user_id varchar(100),
    primary key (okta_group_id, okta_user_id)
);

create table application_approval_queue (
    okta_group_id varchar(100),
    okta_user_id varchar(100),
    okta_app_id varchar(100),
    primary key (okta_group_id, okta_user_id, okta_app_id)
);

create table user_partner_role (
    okta_user_id varchar(100),
    okta_group_id varchar(100),
    partner_role varchar(20),
    primary key (okta_group_id, okta_user_id)
);

create table partner_profile (
    okta_group_name varchar(255),
    group_zipcode varchar(6)
);

create table role (
    name varchar(20) primary key
);

insert into role values ("USER");
insert into role values ("ADMIN");

insert into partner_profile values ("Jame Davis Toyota", "60626");
insert into partner_profile values ("Jeremy Smith Chevy", "60651");

