# Fresh-process metadata qualification supplement

The `run.py` terminal metadata cells establish local close/no-save/no-delivery on a 503. Their final discovery counter does not establish that the named endpoint outage or absent endpoint caused it: earlier flows can consume the two-flight/30-second discovery allowance, and a held-back discovery result is consistent with those counters. Those cells therefore do not show that the endpoint fault caused the 503.

`run_metadata.py` is a separate fresh-process supplement with the same explicit artifact/runtime inputs. It starts with zero discovery requests, obtains one genuine OP/PKCE/signature-authenticated fixture session (one discovery flight), advances the fixture clock 61 seconds and arms outage or unsupported metadata, then starts local logout. Success requires a second actual discovery flight, exact local session closure, no pending save/consume/provider logout/token retry, redacted 503 and only cookie deletion. It creates no browser/provider-session termination proof and keeps the same component, transport, durable-storage and final-release limits as `run.py`.

Run both `--metadata-fault outage` and `--metadata-fault unsupported` in separate fresh output/process instances. The supplement does not modify the carrier, `run.py`, its artifact selections or earlier receipts. It never stages or commits files.
