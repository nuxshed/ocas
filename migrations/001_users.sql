create table users (
    id        uuid primary key default gen_random_uuid(),
    email     text not null unique,
    rollnum   text unique,
    passhash  text not null,
    batch     integer,
    branch    text,
    type      text not null,
    verified  boolean not null default false,
    banned    boolean not null default false,
    createdat timestamptz not null default now()
);
