create table clients (
    clientid     text primary key,
    secrethash   text not null,
    redirecturis text[] not null,
    name         text not null,
    createdat    timestamptz not null default now()
);
