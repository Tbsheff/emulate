import { Store, type Collection } from "@internal/core";
import type { IdpUser, IdpGroup, IdpClient, IdpSigningKey } from "./entities.js";

export interface IdpStore {
  users: Collection<IdpUser>;
  groups: Collection<IdpGroup>;
  clients: Collection<IdpClient>;
  signingKeys: Collection<IdpSigningKey>;
}

export function getIdpStore(store: Store): IdpStore {
  return {
    users: store.collection<IdpUser>("idp.users", ["uid", "email"]),
    groups: store.collection<IdpGroup>("idp.groups", ["name"]),
    clients: store.collection<IdpClient>("idp.clients", ["client_id"]),
    signingKeys: store.collection<IdpSigningKey>("idp.signing_keys", ["kid"]),
  };
}
