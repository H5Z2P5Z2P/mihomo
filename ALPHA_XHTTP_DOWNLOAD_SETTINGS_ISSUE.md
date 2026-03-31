# Alpha XHTTP download-settings Issue

## Summary

Alpha's `xhttp-opts.download-settings` implementation does not follow Xray's `downloadSettings` semantics.
Xray treats download settings as a fully independent downstream `streamSettings`, while Alpha merged it as a partial override on top of upload-side settings.

This breaks split XHTTP cases where upload and download intentionally use different endpoints and different transport identity, especially:

- upload: CDN + TLS XHTTP
- download: REALITY -> fallback -> XHTTP

## Expected Behavior

Reference:

- `Xray-core/transport/internet/splithttp/dialer.go`
- `xhttp.md`

Xray builds an entirely separate download-side configuration from `downloadSettings`:

- separate destination address and port
- separate TLS or REALITY settings
- separate request host derivation
- separate HTTP client / XMUX state

When download-side `xhttpSettings.host` is empty, host selection is still based on the download side only:

`download host -> download serverName -> download address`

Upload-side `host`, `serverName`, TLS settings, and request headers must not leak into the download side.

## Alpha Problem

Before this fix, Alpha used upload-side fallback for download-side fields in `adapter/outbound/vless.go`.

Examples of incorrect inheritance:

- `downloadServer := lo.FromPtrOr(ds.Server, v.option.Server)`
- `downloadPort := lo.FromPtrOr(ds.Port, v.option.Port)`
- `downloadServerName := lo.FromPtrOr(ds.ServerName, v.option.ServerName)`
- `downloadHost := lo.FromPtrOr(ds.Host, v.option.XHTTPOpts.Host)`
- download TLS / ALPN / ECH / REALITY / fingerprint fields also inherited upload-side values

This means a download-side REALITY request could still carry upload-side HTTP host or upload-side TLS identity.
That is protocol-wrong for XHTTP split mode and can break REALITY fallback chains.

## Fix Scope

This fix changes Alpha's outbound VLESS XHTTP handling so that download-side dialing is derived from `download-settings` itself:

- `download-settings.server` is required
- `download-settings.port` is required
- request host is derived only from the download side
- download-side TLS and REALITY fields no longer inherit upload-side values
- download-side request path / headers / xhttp options are read from download settings only

The rest of Alpha's XHTTP transport behavior is left unchanged.

## Tests Added

- direct unit test ensuring download-side `server`, `host`, and `servername` stay independent from upload-side values
- inbound tests updated so `download-settings` explicitly carries the fields it now requires
- added a REALITY + XHTTP + download-settings inbound test

## Note For splithttp-anyreality

The current `splithttp-anyreality` dialing logic is already closer to Xray because upload and download dialing are built independently.

Current recommendation for that branch:

- keep `download-settings.server` and `download-settings.port` as the endpoint fields
- keep upload/download dialing fully independent
- do not inherit upload-side `host`, `servername`, TLS, REALITY, or request headers into download-side dialing
- keep download-side `path` and `host` explicit when the deployment needs them, instead of silently falling back to upload-side values
