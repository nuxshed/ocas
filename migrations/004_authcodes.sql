create table authcodes (
    code          text primary key,
    clientid      text not null references clients(clientid),
    userid        uuid not null references users(id),
    redirecturi   text not null,
    codechallenge text not null,
    expiresat     timestamptz not null,
    used          boolean not null default false
);
