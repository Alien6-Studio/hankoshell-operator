# Deployment security

See [deployment requirements](https://github.com/Alien6-Studio/hankoshell-operator#deployment) and
[private vulnerability reporting](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/SECURITY.md). The admission manifest
currently protects the `auth` namespace; adapt and review that binding before
installing elsewhere. No policy-administration capability is granted to the
operator by this chart.
