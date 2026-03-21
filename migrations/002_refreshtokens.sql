create table refreshtokens (
    id        uuid primary key default gen_random_uuid(),
    tokenhash text not null unique,
    userid    uuid not null references users(id) on delete cascade,
    clientid  text,
    expiresat timestamptz not null,
    createdat timestamptz not null default now()
);
