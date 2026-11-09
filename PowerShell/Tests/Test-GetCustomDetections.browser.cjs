const vm = require("node:vm");
const fs = require("node:fs");
const assert = require("node:assert/strict");
const inputs = JSON.parse(fs.readFileSync(0, "utf8"));
let passed = 0;
const check = (condition) => { assert.ok(condition); passed++; };
const tenant = "11111111-1111-1111-1111-111111111111";
function token(tid = tenant, aud = "https://management.core.windows.net/", exp = Date.now() / 1000 + 3600) {
  return "Bearer " + ["header", Buffer.from(JSON.stringify({ tid, aud, exp })).toString("base64url"), "signature"].join(".");
}
function browser(source = inputs.observer, gov = false, originOverride) {
  const calls = [];
  let httpStatus = 200;
  let throwFetch = false;
  let metadataBody = "{}";
  const location = { origin: originOverride || (gov ? "https://portal.azure.us" : "https://portal.azure.com") };
  location.href = location.origin + "/#@" + tenant;
  class XHR {
    open() {}
    setRequestHeader() {}
    send() {}
  }
  const window = { fetch: async (url, init) => {
    calls.push({ url: String(url), init });
    if (throwFetch) throw new Error("synthetic CORS or redirect failure");
    return { status: httpStatus, text: async () =>
      String(url).includes("/providers/Microsoft.SecurityInsights?") ? metadataBody : '{"value":[]}' };
  }};
  const fetchCachedBeforeObserver = window.fetch;
  const context = vm.createContext({
    window, location, XMLHttpRequest: XHR, WeakMap, URL, Headers, Request,
    TextDecoder, Uint8Array, atob, Date, JSON, Object, Number, String
  });
  vm.runInContext(source, context);
  const cfg = JSON.parse(source.match(/const cfg = (.*);/)[1]);
  return { window, calls, XHR, cfg, context, setStatus: value => { httpStatus = value; },
    setFailure: value => { throwFetch = value; }, setMetadata: value => { metadataBody = value; },
    location, fetchCachedBeforeObserver };
}
(async () => {
  // A portal application that cached fetch before late instrumentation bypasses it.
  const cached = browser();
  await cached.fetchCachedBeforeObserver("https://management.azure.com/batch",
    { headers: { Authorization: token() } });
  check((await cached.window.__sentinelExporter()).status === "waiting");
  // Startup instrumentation runs before the application caches its fetch reference.
  const fetchCachedAfterObserver = cached.window.fetch;
  await fetchCachedAfterObserver("https://management.azure.com/batch",
    { headers: { Authorization: token() } });
  check((await cached.window.__sentinelExporter()).status === "ready");
  const serialized = browser();
  const installedFetch = serialized.window.fetch;
  const installedBridge = serialized.window.__sentinelExporter;
  vm.runInContext(inputs.observer, serialized.context);
  check(serialized.window.fetch === installedFetch && serialized.window.__sentinelExporter === installedBridge);
  await serialized.window.fetch("https://management.azure.com/batch",
    { headers: { Authorization: token() } });
  const serializedPoll = await vm.runInContext(inputs.protocolPollExpression, serialized.context);
  check(typeof serializedPoll === "string" && JSON.parse(serializedPoll).status === "ready");
  const serializedRequest = inputs.protocolPollExpression.replace('__sentinelExporter("")',
    "__sentinelExporter(" + JSON.stringify(serialized.cfg.ListUrl) + ")");
  const serializedPage = await vm.runInContext(serializedRequest, serialized.context);
  check(typeof serializedPage === "string" && JSON.parse(serializedPage).body === '{"value":[]}');
  check(!serializedPage.includes("Bearer") && !serializedPage.includes("signature"));
  const b = browser();
  check((await b.window.__sentinelExporter()).status === "waiting");
  await b.window.fetch("https://example.invalid", { headers: { Authorization: token() } });
  check((await b.window.__sentinelExporter()).status === "waiting");
  const originalBearer = token();
  await b.window.fetch("https://management.azure.com/batch?api-version=2020-06-01",
    { method: "POST", headers: { Authorization: originalBearer } });
  check((await b.window.__sentinelExporter()).status === "ready");
  const reply = await b.window.__sentinelExporter(b.cfg.ListUrl);
  check(reply.status === "ok" && reply.body === '{"value":[]}');
  check(!JSON.stringify(reply).includes("Bearer") && !JSON.stringify(reply).includes("signature"));
  const call = b.calls.at(-1);
  check(call.init.method === "GET" && call.init.redirect === "error" && call.init.credentials === "omit");
  check(call.init.headers.Authorization === originalBearer);
  for (const url of [
    b.cfg.ListUrl.replace("management.azure.com", "example.invalid"),
    b.cfg.ListUrl.replace("management.azure.com", "management.usgovcloudapi.net"),
    b.cfg.ListUrl.replace("https:", "http:"),
    b.cfg.ListUrl.replace("Test-Workspace", "Other-Workspace"),
    b.cfg.ListUrl.replace("management.azure.com", "user@management.azure.com"),
    b.cfg.ListUrl.replace("management.azure.com", "management.azure.com:444"),
    b.cfg.ListUrl + "#fragment", b.cfg.ListUrl + "&api-version=2025-09-01"
  ]) {
    const count = b.calls.length;
    check((await b.window.__sentinelExporter(url)).status === "unsafeUrl" && count === b.calls.length);
  }
  for (const status of [401, 403, 429, 500]) {
    b.setStatus(status);
    const reply = await b.window.__sentinelExporter(b.cfg.ListUrl);
    check(reply.status === "httpError" && reply.httpStatus === status && !reply.body);
  }
  b.setFailure(true);
  check((await b.window.__sentinelExporter(b.cfg.ListUrl)).status === "browserRequestFailed");
  b.setFailure(false);
  b.setStatus(200);
  for (const value of [
    token("33333333-3333-3333-3333-333333333333"),
    token(tenant, "https://api.security.microsoft.com"),
    token(tenant, "https://management.usgovcloudapi.net"),
    token(tenant, "https://management.core.windows.net/", 1), "Bearer not-a-jwt",
    token().replace("Bearer ", "Bearer  "),
    token().replace("Bearer ", "Basic "), token().replace("Bearer ", "Bearer\t")
  ]) {
    await b.window.fetch("https://management.azure.com/batch", { headers: { Authorization: value } });
    check((await b.window.__sentinelExporter()).status === "wrongIdentity");
    check((await b.window.__sentinelExporter(b.cfg.ListUrl)).status === "authUnavailable");
  }
  const req = new Request("https://management.azure.com/batch", { headers: { Authorization: token() } });
  await b.window.fetch(req);
  check((await b.window.__sentinelExporter()).status === "ready");
  await b.window.fetch("https://management.azure.com/batch", { headers: { Authorization: token().replace("Bearer ", "bEaReR ") } });
  check((await b.window.__sentinelExporter()).status === "ready");
  b.location.origin = "https://example.invalid";
  check((await b.window.__sentinelExporter(b.cfg.ListUrl)).status === "wrongPortal");
  const xhr = browser();
  const x = new xhr.XHR();
  x.open("POST", "https://management.azure.com/batch");
  x.setRequestHeader("authorization", token());
  x.send();
  check((await xhr.window.__sentinelExporter()).status === "ready");
  const g = browser(inputs.govObserver, true);
  check(Array.isArray(g.cfg.BrowserOrigins));
  await g.window.fetch("https://management.usgovcloudapi.net/batch",
    { headers: { Authorization: token(tenant, "https://management.core.usgovcloudapi.net/") } });
  check((await g.window.__sentinelExporter(g.cfg.ListUrl)).status === "ok");
  await g.window.fetch("https://management.usgovcloudapi.net/batch",
    { headers: { Authorization: token(tenant, "https://management.usgovcloudapi.net/") } });
  check((await g.window.__sentinelExporter(g.cfg.ListUrl)).status === "ok");
  check(g.calls.filter(call => call.url.includes("/providers/Microsoft.SecurityInsights?")).length === 0);
  const metadata = cfg => ({ id: cfg.ProviderId, namespace: "Microsoft.SecurityInsights",
    resourceTypes: [{ resourceType: "alertRules",
      apiVersions: ["2023-02-01", "2024-03-01", "2025-09-01-preview"] }] });
  const authorizeGovernment = async realm => {
    await realm.window.fetch("https://management.usgovcloudapi.net/batch",
      { headers: { Authorization: token(tenant, "https://management.core.usgovcloudapi.net/") } });
  };
  const automatic = browser(inputs.govAutoObserver, true);
  check(automatic.cfg.ApiVersion === "" && automatic.cfg.ListUrl === "");
  check((await automatic.window.__sentinelExporter("discoverApiVersion")).status === "authUnavailable");
  check(automatic.calls.length === 0);
  automatic.setMetadata(JSON.stringify(metadata(automatic.cfg)));
  await authorizeGovernment(automatic);
  const selectedVersion = await automatic.window.__sentinelExporter("discoverApiVersion");
  check(selectedVersion.status === "apiVersionSelected" && selectedVersion.apiVersion === "2024-03-01");
  check(!JSON.stringify(selectedVersion).includes("Bearer") && !selectedVersion.body);
  const providerCall = automatic.calls.at(-1);
  check(providerCall.url === automatic.cfg.ProviderMetadataUrl && providerCall.init.method === "GET" &&
    providerCall.init.credentials === "omit" && providerCall.init.redirect === "error");
  const selectedUrl = "https://management.usgovcloudapi.net" + automatic.cfg.CollectionPath + "?api-version=2024-03-01";
  check((await automatic.window.__sentinelExporter(selectedUrl)).status === "ok");
  const beforeBadVersion = automatic.calls.length;
  check((await automatic.window.__sentinelExporter(selectedUrl.replace("2024-03-01", "2025-09-01"))).status === "unsafeUrl");
  check(automatic.calls.length === beforeBadVersion);
  // A fresh frame retains the unresolved startup config after context recovery.
  const recoveredGovernment = browser(inputs.govAutoObserver, true);
  recoveredGovernment.setMetadata(JSON.stringify(metadata(recoveredGovernment.cfg)));
  await authorizeGovernment(recoveredGovernment);
  check((await recoveredGovernment.window.__sentinelExporter(selectedUrl)).status === "ok");
  check(recoveredGovernment.calls.length === 3); // Portal request, metadata, rule GET.
  const changedGovernment = browser(inputs.govAutoObserver, true);
  const changedMetadata = metadata(changedGovernment.cfg);
  changedMetadata.resourceTypes[0].apiVersions = ["2023-02-01"];
  changedGovernment.setMetadata(JSON.stringify(changedMetadata));
  await authorizeGovernment(changedGovernment);
  check((await changedGovernment.window.__sentinelExporter(selectedUrl)).status === "unsafeUrl");
  check(changedGovernment.calls.length === 2); // No rule GET with a changed version.
  for (const tamper of [
    url => url.replace("management.usgovcloudapi.net", "example.invalid"),
    url => url.replace("22222222", "33333333"),
    url => url.replace("2021-04-01", "2020-01-01")
  ]) {
    const badSource = inputs.govAutoObserver.replace(JSON.stringify(automatic.cfg.ProviderMetadataUrl),
      JSON.stringify(tamper(automatic.cfg.ProviderMetadataUrl)));
    const unsafeMetadata = browser(badSource, true);
    await authorizeGovernment(unsafeMetadata);
    check((await unsafeMetadata.window.__sentinelExporter("discoverApiVersion")).status === "unsafeUrl");
    check(unsafeMetadata.calls.length === 1);
  }
  for (const status of [401, 403]) {
    const denied = browser(inputs.govAutoObserver, true);
    await authorizeGovernment(denied);
    denied.setStatus(status);
    const deniedReply = await denied.window.__sentinelExporter("discoverApiVersion");
    check(deniedReply.status === "httpError" && deniedReply.httpStatus === status && !deniedReply.body);
    check(denied.calls.length === 2);
  }
  for (const alter of [
    value => { value.id = value.id.replace("22222222", "33333333"); },
    value => { value.namespace = "Microsoft.Compute"; },
    value => { value.resourceTypes = {}; },
    value => { value.resourceTypes[0].resourceType = "incidents"; },
    value => { value.resourceTypes.push(value.resourceTypes[0]); },
    value => { value.resourceTypes[0].apiVersions = ["2024-02-30"]; },
    value => { value.resourceTypes[0].apiVersions = [2024]; }
  ]) {
    const unsupported = browser(inputs.govAutoObserver, true);
    const body = metadata(unsupported.cfg);
    alter(body);
    unsupported.setMetadata(JSON.stringify(body));
    await authorizeGovernment(unsupported);
    check((await unsupported.window.__sentinelExporter("discoverApiVersion")).status === "unsupportedProviderMetadata");
    check(unsupported.calls.length === 2);
  }
  const previewOnly = browser(inputs.govAutoObserver, true);
  const previewMetadata = metadata(previewOnly.cfg);
  previewMetadata.resourceTypes[0].apiVersions = ["2025-09-01-preview"];
  previewOnly.setMetadata(JSON.stringify(previewMetadata));
  await authorizeGovernment(previewOnly);
  check((await previewOnly.window.__sentinelExporter("discoverApiVersion")).status === "apiVersionUnavailable");
  for (const audience of ["https://management.core.windows.net/", "https://api-gov.securitycenter.microsoft.us"]) {
    const invalidGovernment = browser(inputs.govAutoObserver, true);
    await invalidGovernment.window.fetch("https://management.usgovcloudapi.net/batch",
      { headers: { Authorization: token(tenant, audience) } });
    check((await invalidGovernment.window.__sentinelExporter()).status === "wrongIdentity");
    check((await invalidGovernment.window.__sentinelExporter("discoverApiVersion")).status === "authUnavailable");
    check(invalidGovernment.calls.length === 1);
  }
  const governmentInCommercialFrame = browser(inputs.govAutoObserver, false);
  check(!governmentInCommercialFrame.window.__sentinelExporter);
  const unknownGovernmentFrame = browser(inputs.govAutoObserver, true, "https://sandbox-1.reactblade.portal.azure.us");
  check(!unknownGovernmentFrame.window.__sentinelExporter);
  const wrongOrigin = browser(inputs.observer, true);
  check(!wrongOrigin.window.__sentinelExporter);
  const frame = browser(inputs.observer, false, "https://sandbox-1.reactblade.portal.azure.net");
  check((await frame.window.__sentinelExporter()).status === "waiting");
  await frame.window.fetch("https://management.azure.com/batch", { headers: { Authorization: token() } });
  check((await frame.window.__sentinelExporter(frame.cfg.ListUrl)).status === "ok");
  check((await b.window.__sentinelExporter()).status === "wrongPortal");
  const untrustedFrame = browser(inputs.observer, false, "https://sandbox-1.reactblade.portal.azure.net.example.invalid");
  check(!untrustedFrame.window.__sentinelExporter);
  const unverifiedFrame = browser(inputs.observer, false, "https://sandbox-2.reactblade.portal.azure.net");
  check(!unverifiedFrame.window.__sentinelExporter);

  // Exercise the original MDE JavaScript without rewriting its body.
  const mdeSource = inputs.mdeFunction.match(/\$expression = @'\r?\n([\s\S]*?)\r?\n'@/)[1];
  const b64 = value => Buffer.from(value, "utf8").toString("base64");
  const makeMde = async (names, failDetail = false, fixture) => {
    const urls = [];
    const expression = mdeSource.replace("__LIST_URL_BASE64__", b64("/list"))
      .replace("__HEADERS_BASE64__", b64("{}"))
      .replace("__DETECTION_NAMES_BASE64__", b64(JSON.stringify(names)))
      .replaceAll("__EXPECTED_TENANT__", tenant);
    const rules = fixture || [{ Id: 1, Name: "Rule One" }, { Id: 2, Name: "Rule Two" }];
    const context = vm.createContext({
      URL, TextDecoder, Uint8Array, atob, JSON, String, Array, Map, Set, Math, Promise,
      location: { origin: "https://security.apps.mil", href: "https://security.apps.mil/v2/custom_detection?tid=" + tenant },
      fetch: async (url, options) => {
        urls.push(url);
        check(options.credentials === "include");
        if (url === "/list") return { ok: true, json: async () => rules };
        const id = Number(url.match(/\/rules\/([^?]+)\?/)[1]);
        const summary = rules.find(rule => rule?.Id === id);
        const failed = failDetail || summary?.UsxResourceType === "SentinelAnalyticsRule";
        return { ok: !failed, status: failed ? 404 : 200,
          json: async () => ({ id, huntingQuery: { queryText: "print synthetic=1" } }) };
      }
    });
    return { result: JSON.parse(await vm.runInContext(expression, context)), urls };
  };
  let m = await makeMde([]);
  check(m.result.rules.length === 2 && m.result.errors.length === 0 && m.urls.length === 3);
  check(m.result.sourceSelection.legacyCount === 2);
  m = await makeMde(["rule one,Missing"]);
  check(m.result.rules.length === 1 && m.result.notFound[0] === "Missing" && m.urls.length === 2);
  check(m.urls[1].includes("tenantIds=" + tenant) && m.urls[1].includes("includeQuery=true"));
  m = await makeMde(["Rule Two"], true);
  check(m.result.rules.length === 0 && m.result.errors[0].error === "HTTP 404");
  const defender = Array.from({ length: 3 }, (_, index) => ({
    Id: 11 + index, Name: "Defender " + index, UsxSourceType: "Defender",
    UsxResourceType: "DefenderCustomDetectionRule", SourceType: 0
  }));
  const sentinel = Array.from({ length: 249 }, (_, index) => ({
    Id: 100000000 + index, Name: "Sentinel " + index, UsxSourceType: "LogAnalytics",
    UsxResourceType: "SentinelAnalyticsRule", SourceType: 1
  }));
  const mixed = [...defender, ...sentinel];
  m = await makeMde([], false, mixed);
  check(m.result.rules.length === 3 && m.result.summaries.length === 3 && m.result.errors.length === 0);
  check(m.urls.length === 4 && m.urls.slice(1).every(url => /\/rules\/1[123]\?/.test(url)));
  check(m.result.sourceSelection.defenderCount === 3 && m.result.sourceSelection.excludedSentinelCount === 249 &&
    m.result.sourceSelection.unsupportedCount === 0 && m.result.sourceSelection.legacyCount === 0);
  m = await makeMde(["Defender 1,Sentinel 1"], false, mixed);
  check(m.result.rules.length === 1 && m.result.notFound[0] === "Sentinel 1" && m.urls.length === 2);
  m = await makeMde([], false, sentinel);
  check(m.result.rules.length === 0 && m.result.errors.length === 0 && m.urls.length === 1 &&
    m.result.sourceSelection.excludedSentinelCount === 249);
  for (const unsupported of [
    { Id: 91, Name: "Partial", SourceType: 0 },
    { ...defender[0], SourceType: "0" },
    { ...defender[0], UsxSourceType: "Unknown" },
    { ...defender[0], UsxResourceType: "SentinelAnalyticsRule" },
    { ...defender[0], usxSourceType: "LogAnalytics" },
    { Id: 91, Name: "Partial", DetectionRuleSource: "Defender" },
    { Id: 91, Name: "Partial", SourceType: null },
    null, []
  ]) {
    m = await makeMde([], false, [defender[0], unsupported]);
    check(m.result.rules.length === 1 && m.urls.length === 2 &&
      m.result.errors.length === 1 && m.result.errors[0].stage === "classifySummary" &&
      m.result.sourceSelection.unsupportedCount === 1);
  }
  m = await makeMde([], false, [{
    Id: 11, Name: "Lowercase metadata", usxSourceType: "Defender",
    usxResourceType: "DefenderCustomDetectionRule", sourceType: 0
  }]);
  check(m.result.rules.length === 1 && m.result.sourceSelection.defenderCount === 1);
  console.log("Browser JavaScript offline assertions passed: " + passed);
})().catch(error => { console.error(error); process.exitCode = 1; });
