import { describe, it, expect } from "vitest";
import { Store, WebhookDispatcher } from "@internal/core";
import { idpPlugin, seedFromConfig, type IdpSeedConfig } from "../index.js";
import { getIdpStore } from "../store.js";
import { generateSigningKeySync } from "../crypto.js";

describe("idpPlugin", () => {
  it("has correct name", () => {
    expect(idpPlugin.name).toBe("idp");
  });

  it("has register function", () => {
    expect(typeof idpPlugin.register).toBe("function");
  });

  it("has seed function", () => {
    expect(typeof idpPlugin.seed).toBe("function");
  });
});

describe("seedDefaults", () => {
  it("creates default user and signing key", () => {
    const store = new Store();
    idpPlugin.seed!(store, "http://localhost:4003");
    const idp = getIdpStore(store);
    const users = idp.users.all();
    expect(users.length).toBe(1);
    expect(users[0].email).toBe("testuser@example.com");
    expect(users[0].name).toBe("Test User");
    expect(users[0].groups).toEqual([]);
    expect(users[0].roles).toEqual([]);

    const keys = idp.signingKeys.all();
    expect(keys.length).toBe(1);
    expect(keys[0].alg).toBe("RS256");
    expect(keys[0].active).toBe(true);
  });
});

describe("seedFromConfig", () => {
  it("seeds users with correct fields", () => {
    const store = new Store();
    const config: IdpSeedConfig = {
      users: [
        { email: "alice@example.com", name: "Alice", groups: ["admins"], roles: ["owner"], attributes: { dept: "Eng" } },
        { email: "bob@example.com" },
      ],
    };
    seedFromConfig(store, "http://localhost:4003", config);
    const idp = getIdpStore(store);
    const users = idp.users.all();
    expect(users.length).toBe(2);
    expect(users[0].email).toBe("alice@example.com");
    expect(users[0].name).toBe("Alice");
    expect(users[0].groups).toEqual(["admins"]);
    expect(users[0].roles).toEqual(["owner"]);
    expect(users[0].attributes).toEqual({ dept: "Eng" });
    expect(users[0].uid).toBeTruthy();

    expect(users[1].email).toBe("bob@example.com");
    expect(users[1].name).toBe("bob"); // derived from email
    expect(users[1].groups).toEqual([]);
    expect(users[1].roles).toEqual([]);
  });

  it("skips duplicate emails", () => {
    const store = new Store();
    seedFromConfig(store, "http://localhost:4003", {
      users: [{ email: "alice@example.com" }],
    });
    seedFromConfig(store, "http://localhost:4003", {
      users: [{ email: "alice@example.com" }],
    });
    const idp = getIdpStore(store);
    expect(idp.users.all().length).toBe(1);
  });

  it("seeds clients with defaults for optional fields", () => {
    const store = new Store();
    seedFromConfig(store, "http://localhost:4003", {
      oidc: {
        clients: [{
          client_id: "my-app",
          client_secret: "my-secret",
          redirect_uris: ["http://localhost:3000/callback"],
        }],
      },
    });
    const idp = getIdpStore(store);
    const clients = idp.clients.all();
    expect(clients.length).toBe(1);
    expect(clients[0].client_id).toBe("my-app");
    expect(clients[0].client_secret).toBe("my-secret");
    expect(clients[0].redirect_uris).toEqual(["http://localhost:3000/callback"]);
    expect(clients[0].name).toBe("my-app"); // defaults to client_id
    expect(clients[0].post_logout_redirect_uris).toEqual([]);
    expect(clients[0].scopes).toEqual(["openid", "email", "profile"]);
    expect(clients[0].claim_mappings).toEqual({});
    expect(clients[0].access_token_ttl).toBe(3600);
    expect(clients[0].id_token_ttl).toBe(3600);
    expect(clients[0].refresh_token_ttl).toBe(86400);
  });

  it("auto-generates signing key when none provided", () => {
    const store = new Store();
    seedFromConfig(store, "http://localhost:4003", { users: [{ email: "test@test.com" }] });
    const idp = getIdpStore(store);
    expect(idp.signingKeys.all().length).toBe(1);
  });

  it("uses provided signing keys", () => {
    const store = new Store();
    const generated = generateSigningKeySync("provided-kid");
    seedFromConfig(store, "http://localhost:4003", {
      oidc: {
        signing_keys: [{ kid: "provided-kid", private_key_pem: generated.private_key_pem }],
      },
    });
    const idp = getIdpStore(store);
    const keys = idp.signingKeys.all();
    expect(keys.length).toBe(1);
    expect(keys[0].kid).toBe("provided-kid");
  });

  it("stores strict flag", () => {
    const store = new Store();
    seedFromConfig(store, "http://localhost:4003", { strict: true });
    expect(store.getData<boolean>("idp.strict")).toBe(true);
  });

  it("stores custom issuer", () => {
    const store = new Store();
    seedFromConfig(store, "http://localhost:4003", {
      oidc: { issuer: "https://custom-issuer.example.com" },
    });
    expect(store.getData<string>("idp.issuer")).toBe("https://custom-issuer.example.com");
  });

  it("seeds groups", () => {
    const store = new Store();
    seedFromConfig(store, "http://localhost:4003", {
      groups: [{ name: "engineering", display_name: "Engineering Team" }],
    });
    const idp = getIdpStore(store);
    const groups = idp.groups.all();
    expect(groups.length).toBe(1);
    expect(groups[0].name).toBe("engineering");
    expect(groups[0].display_name).toBe("Engineering Team");
  });
});
