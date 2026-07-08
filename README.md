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

## Linking vs. account switch

Use the strict `linkWith*` APIs when attaching email/password or a provider to the current Firebase
user. If the email/provider already belongs to another Firebase user, strict link throws and the
current uid is preserved.

Use `linkAnonymousOrSignInExistingWith*` only for an explicit merge/sign-in flow. These methods first
try to link the anonymous user in place, but on conflict they sign into the existing Firebase account,
which can change the uid. That is dangerous for apps that key local data, backend data, or
subscriptions by Firebase uid unless they have a dedicated merge policy.

The older `signInWith*FromAnonymous` names are deprecated compatibility aliases for
`linkAnonymousOrSignInExistingWith*`.

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

<!-- relux-ecosystem:start -->

## About Relux Works

This project is part of the open-source ecosystem of
[Relux Works](https://relux.works), an AI-native software development studio.
We build fixed-price MVPs, rescue vibe-coded apps, run local AI inference, and
train teams to work with coding agents — and we open-source much of the
infrastructure behind it.

- Full catalog: [relux.works/en/open-source](https://relux.works/en/open-source/)
- Agentic enablement: [agent harnesses & team training](https://relux.works/en/agentic-enablement/)
- Hire us the agent-native way — point your assistant at `https://api.relux.works/mcp`
- Contact: ivan@relux.works

<!-- relux-ecosystem:end -->
