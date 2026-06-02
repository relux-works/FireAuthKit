# FireAuthKit

Firebase Authentication for Apple platforms over the public REST API, without the Firebase SDK.

## Products

- `FireAuthKit` — Foundation-only Firebase Auth REST client.
- `FireAuthKitSocial` — Apple/Google/Facebook/Twitter OAuth credential acquisition. Firebase exchange still happens in `FireAuthKit`.
- `FireAuthProvider` — SDK-neutral provider interface for feature modules.
- `FireAuthProviderImpl` — in-memory provider implementation over `FireAuthKit` and `FireAuthKitSocial`.

## Scope

The core REST surface covers anonymous auth, email/password signup and login, phone REST methods,
generic IdP sign-in, social sign-in/link wrappers, anonymous-to-real upgrade fallback, token refresh,
and email verification.

This package deliberately does not include a backend bridge, profile sync, Keychain persistence, or
Relux state/service/fetcher code. Apps own token storage and app-specific sync.

## Configuration

`FireAuthProvider.Configuration.load(bundle:)` reads Firebase configuration from either app Info.plist
keys or a bundled `GoogleService-Info.plist`. Social provider keys are optional and light up only the
matching demo/provider flows.

## Relux Integration Pattern

```text
SwiftUI -> Relux SideEffect -> Relux Saga -> AuthService (app)
    -> FireAuthProvider.Module.Interface
    -> FireAuthProviderImpl
    -> FireAuthKit / FireAuthKitSocial
    -> Firebase REST
```

The app owns token persistence, state transitions, refresh timing, anonymous-to-real orchestration,
and any backend sync.
