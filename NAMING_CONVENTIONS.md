# Public API Naming Conventions

This document defines naming rules for RevetSec public APIs, including factories, builders, properties, and callback parameters.
It exists to keep future naming decisions consistent and avoid repeated debate.

It is adapted from Soklet's naming conventions. RevetSec core and each RevetSec adapter repository carry identical copies.

## Scope

- Applies to public API design in RevetSec core and its adapters.
- Does not require renaming internal APIs, protocol fields, or the retained exceptions below.

## Rules

- **Builder entrypoints (no required inputs):** use `builder()`.
- **Builder entrypoints (required primary input):** use `withX(...)` and return a `Builder`.
- **Instance factories:** use `fromX(...)` and return a fully built instance (never a builder).
- **Builder convenience:** when a `withX(...)` builder is commonly used with only required inputs, add a `fromX(...)` convenience that calls `withX(...).build()`.
- **Shared singletons and presets:** prefer names that include `Instance` (e.g., `defaultInstance()`, `disabledInstance()`, `microsoftEntraIdInstance()`), but this is not a hard requirement if readability benefits.
- **Defaults (fresh):** use `fromDefaults()` for a new instance configured with defaults.
- **Per-request variants:** an immutable configured object that needs a per-request variant offers `copy()`, which returns a `Copier`; `finish()` returns the new instance.
- **Builder setters:** prefer property-name methods (`clientId(...)`, `redirectUri(...)`).
  Collection and map properties accept complete values, snapshot them before assignment, and replace previous values.
  Passing `null` restores the default. There are no per-item adders and no varargs setters.
  Callers accumulating values should assemble a list and assign it once, not call a replacement setter per item.
- **Accessors:** use `getX()`, or `isX()` for a `Boolean`. Absent values are returned as `Optional`, and numbers and booleans are boxed (`Integer`, `Long`, `Boolean`).
- **Public value types:** use `final` classes with private constructors, never public records.
- **Properties and parameters:** use the full domain name where it distinguishes the value, for example
  `assertionConsumerServiceUrl`, `pendingAuthenticationLifetime`, and `expectedAudiences`.
- **Role types:** name their capability explicitly: `PendingAuthorizationSource`,
  `ClientCredentialsTokenSource`, and `JwtAccessTokenValidator`.
- **Callbacks:** multi-hook callback interfaces are `*Observer` types with `willX`/`didX`/`didFailToX` hooks.
  `*Listener` is reserved for single-method sinks.
- **Secret-emitting methods:** a method that returns a secret says so by name, such as `getValue()`, `toSealedForm()`,
  `toCompactSerialization()`, or `getAuthorizationHeaderValue()`. `toString()` never renders a secret.
- **Adapter helpers:** stateless helper classes use verb or noun methods, such as `authorizationResponseFor(request)`.
- **Avoid** `of*`, `create*`, `new*` for public APIs to keep the search surface uniform.
- **Renames:** until 1.0.0, rename cleanly without a compatibility alias. From 1.0.0, add the new name next to a deprecated alias, and remove the alias only in a major release.

## Retained exceptions

Protocol parameter, claim, attribute, element and schema names (`client_id`, `NameID`, `scimType`) are wire names,
not Java API names, and keep the spelling their specifications give.

Validation exceptions keep a concise nested `Reason` enum, read with `getReason()`.

Servlet-mandated and Soklet-mandated method names in the adapters remain unchanged.

## Examples

The names below come from RevetSec's planned API. They illustrate the rules and may change before the types exist.

```java
// Builder entrypoints
OidcClient oidcClient = OidcClient.withIssuer("https://accounts.google.com")
	.clientId(clientId)
	.redirectUri(URI.create("https://app.example.com/auth/google/callback"))
	.build();
StateSealer stateSealer = StateSealer.withActiveKey(activeKey)
	.verificationKeys(List.of(previousKey))
	.build();
ScimServiceProvider.Builder scimBuilder = ScimServiceProvider.builder();

// Instance factories
SealingKey sealingKey = SealingKey.fromBase64("2026-09", base64Key);
ClientAuthentication clientAuthentication = ClientAuthentication.fromClientSecretBasic(clientSecret);
ScimFilter scimFilter = ScimFilter.fromExpression("userName eq \"bjensen\"");

// Shared singletons and presets
OutboundUriPolicy outboundUriPolicy = OutboundUriPolicy.defaultInstance();
ScimCompatibility scimCompatibility = ScimCompatibility.microsoftEntraIdInstance();

// Defaults
SamlSecurityPolicy samlSecurityPolicy = SamlSecurityPolicy.fromDefaults();

// Per-request variants
ScimServiceProvider tenantScim = scim.copy().baseUri(tenantScimBaseUri).finish();
```
