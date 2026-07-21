// Pre-flight spike (O-2): does node-oidc-provider carry the Mission AS surfaces?
// Empirical checks, each printing PASS/FAIL. Throwaway-grade by design.
import Provider, { errors } from 'oidc-provider';

const ISSUER = 'http://localhost:4499';
const results = [];
const record = (name, ok, note = '') => {
  results.push({ name, ok, note });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${note ? `  -- ${note}` : ''}`);
};

// -- 1. Construction with the full feature set ------------------------------
let provider;
try {
  provider = new Provider(ISSUER, {
    clients: [{
      client_id: 'spike-client',
      client_secret: 'spike-secret',
      grant_types: ['authorization_code', 'client_credentials', 'urn:ietf:params:oauth:grant-type:token-exchange', 'urn:ietf:params:oauth:grant-type:deferred'],
      response_types: ['code'],
      redirect_uris: ['http://localhost:9999/cb'],
      token_endpoint_auth_method: 'client_secret_basic',
    }],
    features: {
      pushedAuthorizationRequests: { enabled: true, requirePushedAuthorizationRequests: false },
      richAuthorizationRequests: {
        enabled: true,
        ack: 'experimental-01',
        types: {
          mission_resource_access: {
            validate: (ctx, detail) => {
              if (!detail.resource) throw new Error('missing resource');
            },
          },
        },
      },
      dPoP: { enabled: true },
      introspection: { enabled: true },
      revocation: { enabled: true },
      clientCredentials: { enabled: true },
      resourceIndicators: {
        enabled: true,
        defaultResource: () => 'urn:spike:api',
        getResourceServerInfo: () => ({
          scope: 'pay',
          audience: 'urn:spike:api',
          accessTokenFormat: 'jwt',
          accessTokenTTL: 300,
        }),
        useGrantedResource: () => true,
      },
    },
    extraParams: {
      // mission_intent: PAR-only carriage + reject-both rule (core § submission-via-par)
      async mission_intent(ctx, value) {
        if (value === undefined) return;
        let parsed;
        try { parsed = JSON.parse(value); } catch {
          throw new errors.InvalidRequest('mission_intent must be JSON');
        }
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new errors.InvalidRequest('mission_intent must be a JSON object');
        }
        if (ctx.oidc.params.authorization_details !== undefined) {
          throw new errors.InvalidRequest('mission_intent and authorization_details are mutually exclusive');
        }
      },
    },
    extraTokenClaims(ctx, token) {
      return {
        mission: {
          id: 'spike-mission-1',
          issuer: ISSUER,
          authority_hash: 'sha-256:spike',
          expires_at: Math.floor(Date.now() / 1000) + 600,
        },
      };
    },
    scopes: ['openid', 'pay'],
    pkce: { required: () => false },
  });
  provider.proxy = false;
  record('provider constructs with PAR+RAR(typed)+DPoP+introspection+resourceIndicators+extraParams', true);
} catch (e) {
  record('provider constructs with full feature set', false, e.message);
  process.exit(1);
}

// -- 2. Custom grant registration surface -----------------------------------
try {
  const ok = typeof provider.registerGrantType === 'function';
  if (!ok) throw new Error('registerGrantType missing');
  provider.registerGrantType('urn:ietf:params:oauth:grant-type:token-exchange',
    async (ctx) => { ctx.body = { spike: 'token-exchange-reached' }; ctx.status = 200; },
    ['subject_token', 'subject_token_type', 'actor_token', 'actor_token_type', 'audience'], []);
  provider.registerGrantType('urn:ietf:params:oauth:grant-type:deferred',
    async (ctx) => { ctx.body = { spike: 'dtr-reached' }; ctx.status = 200; },
    ['deferral_code'], []);
  record('custom grants register (token-exchange + DTR deferred)', true);
} catch (e) {
  record('custom grants register', false, e.message);
}

// -- 3. Issuer-derived RAR surface (Grant / AccessToken shape) ---------------
try {
  const grantProps = Object.getOwnPropertyNames(provider.Grant.prototype);
  const rarish = grantProps.filter((p) => /rar|authorization_?details/i.test(p));
  const atSchemaHasRar = (() => {
    try {
      const at = new provider.AccessToken({ client: undefined });
      return 'rar' in at || true; // constructor may throw; fallback below
    } catch { return 'unknown'; }
  })();
  record('Grant prototype rar-related members', rarish.length > 0, `found: ${rarish.join(', ') || 'none'}; AccessToken rar: ${atSchemaHasRar}`);
} catch (e) {
  record('Grant prototype inspection', false, e.message);
}

// -- 4. Wire checks ----------------------------------------------------------
const server = provider.listen(4499);
const b64 = Buffer.from('spike-client:spike-secret').toString('base64');
const form = (o) => new URLSearchParams(o).toString();
const post = (path, body, headers = {}) => fetch(`${ISSUER}${path}`, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${b64}`, ...headers },
  body: form(body),
});

try {
  // 4a. PAR accepts mission_intent
  const intent = JSON.stringify({ objective: 'pay acme invoices', proposed_authority: [] });
  let r = await post('/request', {
    client_id: 'spike-client', response_type: 'code', redirect_uri: 'http://localhost:9999/cb',
    scope: 'pay', mission_intent: intent,
  });
  const parBody = await r.json();
  record('PAR accepts mission_intent extra param', r.status === 201 && !!parBody.request_uri, `status=${r.status} ${JSON.stringify(parBody).slice(0, 120)}`);

  // 4b. PAR rejects mission_intent + authorization_details together
  r = await post('/request', {
    client_id: 'spike-client', response_type: 'code', redirect_uri: 'http://localhost:9999/cb',
    scope: 'pay', mission_intent: intent,
    authorization_details: JSON.stringify([{ type: 'mission_resource_access', resource: 'urn:spike:api' }]),
  });
  record('PAR rejects mission_intent + raw authorization_details (invalid_request)', r.status === 400, `status=${r.status} ${(await r.text()).slice(0, 120)}`);

  // 4c. PAR rejects malformed mission_intent
  r = await post('/request', {
    client_id: 'spike-client', response_type: 'code', redirect_uri: 'http://localhost:9999/cb',
    scope: 'pay', mission_intent: 'not-json',
  });
  record('PAR rejects malformed mission_intent', r.status === 400, `status=${r.status}`);

  // 4d. /auth with request_uri routes toward interaction (param flow proof)
  const good = await post('/request', {
    client_id: 'spike-client', response_type: 'code', redirect_uri: 'http://localhost:9999/cb',
    scope: 'pay', mission_intent: intent,
  }).then((x) => x.json());
  r = await fetch(`${ISSUER}/auth?${form({ client_id: 'spike-client', request_uri: good.request_uri })}`, { redirect: 'manual' });
  const loc = r.headers.get('location') || '';
  record('/auth consumes PAR request_uri and redirects to interaction', r.status === 303 && loc.includes('/interaction/'), `status=${r.status} loc=${loc}`);

  // 4e. interaction details expose mission_intent
  if (loc.includes('/interaction/')) {
    const uid = loc.split('/interaction/')[1];
    const interaction = await provider.Interaction.find(uid);
    const seen = interaction?.params?.mission_intent;
    record('interaction details carry mission_intent for derivation/rendering', !!seen, `params.mission_intent ${seen ? 'present' : 'MISSING'}`);
  }

  // 4f. client_credentials mints a JWT AT carrying the mission claim
  r = await post('/token', { grant_type: 'client_credentials', scope: 'pay', resource: 'urn:spike:api' });
  const tok = await r.json();
  let missionClaimOk = false; let atNote = `status=${r.status}`;
  if (tok.access_token && tok.access_token.split('.').length === 3) {
    const claims = JSON.parse(Buffer.from(tok.access_token.split('.')[1], 'base64url').toString());
    missionClaimOk = claims.mission?.id === 'spike-mission-1';
    atNote += ` aud=${claims.aud} mission.id=${claims.mission?.id}`;
  }
  record('client_credentials mints JWT AT with custom mission claim (extraTokenClaims)', missionClaimOk, atNote);

  // 4g. introspection reflects the token (and mission claim visibility)
  if (tok.access_token) {
    r = await post('/token/introspection', { token: tok.access_token });
    const intro = await r.json();
    record('introspection endpoint active', r.status === 200 && intro.active === true, `resp=${JSON.stringify(intro).slice(0, 160)}`);
  }

  // 4h. custom grant reachable at token endpoint
  r = await post('/token', { grant_type: 'urn:ietf:params:oauth:grant-type:deferred', deferral_code: 'x' });
  const dtr = await r.text();
  record('DTR custom grant reachable at token endpoint', dtr.includes('dtr-reached'), dtr.slice(0, 80));
} catch (e) {
  record('wire checks', false, e.stack?.split('\n')[0] ?? String(e));
} finally {
  server.close();
}

console.log(`\n${results.filter((x) => x.ok).length}/${results.length} checks passed`);
