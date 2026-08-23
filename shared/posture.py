# ZTLab - in-process device/workload posture self-check.
#
# Computed once at process startup (zero per-request network/API overhead —
# this is a static property of how the container was launched, not something
# that changes request-to-request) and attached as the X-Device-Posture
# header on outbound calls that opa/policies/zta_policy.rego's
# `posture_compliant` rule inspects.
#
# Scope note: this only checks effective capabilities, not image tag
# pinning. Kubernetes' Downward API has no field for a container's own image
# reference (confirmed by trying — `fieldRef: spec.containers[0].image` is
# rejected with "field label not supported"), so a process genuinely cannot
# introspect that about itself. Image-tag pinning is instead checked
# externally by k8s/financial/posture-agent-cronjob.yaml, which reads full
# pod specs via the K8s API and doesn't have this limitation.
#
# Compliance bar matches that CronJob's: NOT "must run as non-root" (every
# service here runs as uid=0 with no securityContext set — enforcing that
# would 403 all real traffic today), only a genuinely dangerous signal:
# capabilities beyond Docker's default set.

_DANGEROUS_CAPS = {"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE", "ALL"}

_CAP_BIT_NAMES = {
    12: "NET_ADMIN",
    16: "SYS_MODULE",
    19: "SYS_PTRACE",
    21: "SYS_ADMIN",
}


def _effective_capability_names() -> set[str]:
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    cap_eff = int(line.split()[1].strip(), 16)
                    return {name for bit, name in _CAP_BIT_NAMES.items() if cap_eff & (1 << bit)}
    except Exception:
        pass
    return set()


def compute_device_posture() -> tuple[str, list[str]]:
    """Returns (posture, reasons) where posture is 'compliant' or 'non-compliant'."""
    reasons: list[str] = []

    dangerous = _effective_capability_names() & _DANGEROUS_CAPS
    if dangerous:
        reasons.append("dangerous_capability:" + ",".join(sorted(dangerous)))

    return ("non-compliant" if reasons else "compliant"), reasons


DEVICE_POSTURE, DEVICE_POSTURE_REASONS = compute_device_posture()
