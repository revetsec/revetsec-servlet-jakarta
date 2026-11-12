# Provider-token application carrier qualification

Run `calibrate.py` against the reviewed Tomcat runtime and an explicit selected
core JAR/SHA256 pair. See [the application recipe](../../docs/provider-tokens.md)
for deployment contracts and commands. `run.py` runs one positive source-bound
workload; `calibrate.py` also verifies three private defect detections. Both stop
and remove every owned process/instance. Fixture control/signing endpoints require
a disposable credential and must not ship in an application.

The namespace twins differ only in Servlet imports and their reviewed runtime
pin. The common backend policy is authored once in core's unpublished
`examples/provider-backend-tokens` directory. These local synthetic-provider
checks establish no hosted-provider/native-device or full S1-S4 formal M12 claim.
