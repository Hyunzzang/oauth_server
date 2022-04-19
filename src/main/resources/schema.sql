-- oauth 사용할 클라이언트 정보 테이블
CREATE TABLE IF NOT EXISTS `oauth_client_details` (
    `client_id` VARCHAR(256) NOT NULL,
    `resource_ids` VARCHAR(256) NULL,
    `client_secret` VARCHAR(256) NULL,
    `scope` VARCHAR(256) NULL,
    `authorized_grant_types` VARCHAR(256) NULL,
    `web_server_redirect_uri` VARCHAR(256) NULL,
    `authorities` VARCHAR(256) NULL,
    `access_token_validity` INT NULL,
    `refresh_token_validity` INT NULL,
    `additional_information` VARCHAR(4096) NULL,
    `autoapprove` VARCHAR(256) NULL,
    PRIMARY KEY (`client_id`)
    );

insert into oauth_client_details(client_id, resource_ids,client_secret,scope,authorized_grant_types,web_server_redirect_uri,authorities,access_token_validity,refresh_token_validity,additional_information,autoapprove)
values('testapp',null,'{bcrypt}$2a$10$EMaBP3/uvgUw36uSnW0w0OVjjKk/GrP6mnwBpbditd5ZWUoiPXPTO','read,write,profile,email','authorization_code,password,client_credentials,implicit,refresh_token','http://localhost:8080/oauth2/callback','ROLE_USER',36000,50000,null,null);


-- 토큰 정보 테이블
create table IF NOT EXISTS oauth_client_token (
    token_id VARCHAR(256),
    token BLOB,
    authentication_id VARCHAR(256) PRIMARY KEY,
    user_name VARCHAR(256),
    client_id VARCHAR(256)
    );

create table IF NOT EXISTS oauth_access_token (
    token_id VARCHAR(256),
    token BLOB,
    authentication_id VARCHAR(256) PRIMARY KEY,
    user_name VARCHAR(256),
    client_id VARCHAR(256),
    authentication BLOB,
    refresh_token VARCHAR(256)
    );

create table IF NOT EXISTS oauth_refresh_token (
    token_id VARCHAR(256),
    token BLOB,
    authentication BLOB
    );

create table IF NOT EXISTS oauth_code (
    code VARCHAR(256), authentication BLOB
    );

create table IF NOT EXISTS oauth_approvals (
    userId VARCHAR(256),
    clientId VARCHAR(256),
    scope VARCHAR(256),
    status VARCHAR(10),
    expiresAt TIMESTAMP,
    lastModifiedAt TIMESTAMP
    );
