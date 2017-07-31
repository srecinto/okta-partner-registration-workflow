

create table partner_approval_queue (
    okta_group_id varchar(100),
    okta_user_id varchar(100),
    primary key (okta_group_id, okta_user_id)
);

create table user_partner_role (
    okta_user_id varchar(100),
    okta_group_id varchar(100),
    partner_role varchar(20),
    primary key (okta_group_id, okta_user_id)
);
