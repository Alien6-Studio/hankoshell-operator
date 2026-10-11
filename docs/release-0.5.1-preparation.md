# Historical 0.5.1 source preparation — superseded

PRs #54 and #55 qualified release-trust hardening and source metadata under the
provisional 0.5.1 model. Main fac8b683e30453e980c5dec8ebab8e963be0d74c was qualified,
but no v0.5.1 tag, GitHub Release or production package was created.

That model and its tag-readiness decision were canceled before tag creation.
The active product version is now public 0.1.0, consolidating all qualified
engineering checkpoints without a functional rollback. Public tags use the
separate release/v<SemVer> namespace, starting with release/v0.1.0. The historical
v0.1.0 through v0.5.0 source tags remain signed, unchanged and unpublished.

Use the [public 0.1.0 preparation and administrator checklist](release-public-0.1.0-preparation.md).
No tag, production trust provisioning, Release dispatch or publication is
authorized by this historical document. #21 remains open for external evidence.
